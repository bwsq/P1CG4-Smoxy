import os, sys, subprocess, sqlite3, time, ast, json, signal
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
from broxy import launch_broxy
from bs4 import BeautifulSoup
from config import (DATABASE_FILE, mitm_port, flask_port, toggle_interception,
                    get_interception_enabled, stringToBoolean, set_resume_signal,
                    set_drop_signal)

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# Run Proxy and Browser Python script
if os.path.exists(DATABASE_FILE):
    os.remove(DATABASE_FILE)
    print(f"refreshed {DATABASE_FILE}")
else:
    print(f"No prior {DATABASE_FILE}")

# Instantiate Intercept, Resume and drop flag values
with open('intercept.txt', 'w') as file:
    file.write('False')
with open('resume.txt', 'w') as file:
    file.write('False')
with open('drop.txt', 'w') as file:
    file.write('False')

try:
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS traffic (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            flow_type TEXT,  -- 'request' or 'response'
            url TEXT,
            path TEXT,
            status_code INT,
            reason TEXT,
            port TEXT,
            method TEXT,
            scheme TEXT,
            http_version TEXT,
            headers TEXT,
            content_type TEXT,
            content BLOB,
            trailers TEXT,
            is_modified INTEGER DEFAULT 0,  -- 0 for not modified, 1 for modified
            intercepted INTEGER DEFAULT 0, -- 0 for not intercepted, 1 intercepted
            flag TEXT,
            vulnerability TEXT,
            action TEXT -- whether it is dropped or forwarded 
        )
        """
    )
    conn.commit()
    conn.close()
except sqlite3.Error as e:
    print(f"Database error: {e}")

# Runs MITMPROXY Verbose version, uncomment if you want to use this version then comment the one below
processes = (["mitmdump", "-p", mitm_port, "-s", "proxy.py"],
             ["python", "broxy.py"])

# processes = (["mitmdump", "-p", mitm_port, "--set", "flow_detail=0", "-s", "proxy.py"],
#              ["python", "broxy.py"])


proc_list = []


def start_processes():
    if not os.environ.get('WERKZEUG_RUN_MAIN'):  # Prevents duplicate execution caused by flask debug mode
        for process in processes:
            proc_list.append(subprocess.Popen(process))
            time.sleep(2)  # ensure mitmproxy running
            print(f"[!] {process[-1]} running\n")


def stop_processes():
    for proc in proc_list:
        try:
            proc.terminate()  # Try to terminate the process
            proc.wait()  # Ensure the process is fully stopped
            print(f"Terminated {proc.pid}")
        except Exception as e:
            print(f"Error terminating process {proc.pid}: {e}")


# Signal handler to catch SIGINT (Ctrl-C)
def handle_sigint():
    print("\nInterrupt received. Stopping processes...")
    stop_processes()
    sys.exit(0)  # Exit cleanly


# Register Signal Handler
signal.signal(signal.SIGINT, handle_sigint)


# FLASK STUFF - Control Panel
@app.route("/")
def home():
    interception_enabled = stringToBoolean(get_interception_enabled())
    print(f"interception_enabled in App.py first one {type(interception_enabled)} {interception_enabled}")
    if interception_enabled:
        intercept_state = 'Enabled'
    else:
        intercept_state = 'Disabled'
    return render_template("index.html",
                           mitm_port=mitm_port,
                           interception_enabled=intercept_state,
                           information=None
                           )


@app.route("/open_browser", methods=['GET', 'POST'])
def open_browser():
    print("Launching a browser instance")
    launch_broxy()
    return "Browser Opened"


@app.route("/toggle-intercept", methods=['POST'])
def toggle_intercept():
    print("Toggling intercept")
    state = toggle_interception()  # Call the function from proxy.py, returns enabled or disabled
    print(f"State Change : {state}")
    return state  # Return the state of the variable


@app.route("/forward", methods=['GET'])
def forward():
    print("Forward button pressed")
    set_resume_signal('True')
    return "Forwarded"


@app.route("/drop", methods=['GET'])
def drop():
    print("Drop button pressed")
    set_resume_signal(True)
    set_drop_signal(True)
    return "Dropped"


@app.route("/incoming-flow", methods=['POST'])
def incoming_flow():
    print("New incoming Flow!")

    interception_enabled = stringToBoolean(get_interception_enabled())
    if interception_enabled:
        intercept_state = 'Enabled'
    else:
        intercept_state = 'Disabled'

    # flow_type = request.args.get('type') if request else None
    flow_type = request.json.get('type')

    # Get ID corresponding to current intercepted traffic
    response = query_database("SELECT MAX(id) FROM traffic")
    id = response[0][0] if response else None

    information = {}  # store packet info as a dict for frontend
    information['id'] = id

    if flow_type == 'request':
        information['type'] = 'request'

        # handles method (GET, POST, PUT)
        response = query_database(f"SELECT method FROM traffic WHERE id = {id}")
        information['method'] = response[0][0] if response else None

        # handles path
        response = query_database(f"SELECT path FROM traffic WHERE id = {id}")
        if response[0][0] == '/':
            response[0][0] == None
        information['path'] = response[0][0] if response else None

        # handles url (parse to seperate host from path)
        response = query_database(f"SELECT url FROM traffic WHERE id = {id}")  # need to process to display host
        information['url'] = response[0][0] if response else None

    elif flow_type == 'response':

        information['type'] = 'response'
        # handles status code
        response = query_database(f"SELECT status_code FROM traffic WHERE id = {id}")
        information['status_code'] = response[0][0] if response else None

        # handles status reason/message
        response = query_database(f"SELECT reason FROM traffic WHERE id = {id}")
        information['reason'] = response[0][0] if response else None

    # handle headers (need to be parsed in frontend)
    response = query_database(f"SELECT headers FROM traffic WHERE id = {id}")  # dictionary of headers
    information['headers'] = ast.literal_eval(response[0][0]) if response else None
    print(information['headers'])

    # handles HTTP version (HTTP/2.0)
    response = query_database(f"SELECT http_version FROM traffic WHERE id = {id}")
    information['http_version'] = response[0][0] if response else None

    # Handles content type (if any)
    content_type = None
    for key in information['headers'].keys():
        if key.lower() == 'content-type':
            content_type = information['headers']['content-type']  # must account for Content-Type and content-type in headers
            information['content-type'] = content_type
            print(content_type)
            break

    # Handles content  (if any)
    content = None
    if content_type:
        data = query_database(f"SELECT content FROM traffic WHERE id = {id}")  # get content
        if data:
            content = decode_content(content_type, data)
        else:
            content = None

    if content:
        information['content'] = content

    print(information)

    socketio.emit('info', information)

    return jsonify({"message" : "Received"}), 200

    # return render_template("index.html",
    #                        mitm_port=mitm_port,
    #                        interception_enabled=intercept_state,
    #                        requestandheaders=jsonify(information or {"message": "No traffic yet"})
    #                        )


@app.route("/traffic/<int:traffic_id>", methods=['GET', 'POST'])
def view_traffic(traffic_id):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()

    if request.method == 'POST':  # Edit submission
        modified_data = request.form['traffic_data']
        cursor.execute("UPDATE traffic SET data = ?, is_modified = 1 WHERE id = ?", (modified_data, traffic_id))
        conn.commit()

        # Create resume.txt to resume the flow
        with open("resume.txt", "w") as f:
            f.write("resume")  # can add other data if needed.

        conn.close()
        return "Traffic modified and resumed"

    # GET request: Retrieve traffic data for display
    cursor.execute("SELECT flow_type, url, data FROM traffic WHERE id = ?", (traffic_id,))
    traffic = cursor.fetchone()
    conn.close()

    if traffic:
        flow_type, url, data = traffic
        # Pretty print the JSON data (optional)
        try:
            data_pretty = json.dumps(json.loads(data), indent=4)  # Parse and re-serialize for formatting
        except json.JSONDecodeError:
            data_pretty = data  # If it's not JSON, display as is

        return render_template("view_traffic.html", traffic_id=traffic_id, flow_type=flow_type, url=url,
                               traffic_data=data_pretty)
    else:
        return "Traffic not found"


def query_database(query):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute(query)
    data = cursor.fetchall()
    conn.close()
    return data

    # Handle different content types


def decode_content(content_type, data):
    content_type = content_type.lower()
    data = data[0][0]

    if 'application/json' in content_type:
        print("Handling JSON data")
        # decode into string and remove the non-JSON part (prefix)
        # json_string = data.decode('utf-8')[4:]
        if b")]}\'" in data:
            json_string = data.decode('utf-8')[4:]
        else:
            json_string = data.decode('utf-8')
        json_data = json.loads(json_string)
        # print(type(json_data))  # dict
        # for key in json_data:
        #     if json_data[f'{key}']:
        #         item = json_data[f'{key}']
        #         if type(item) is list:
        #             for i in item:
        #                 print(f'{i}\n')

        json_load = json.loads(json_string)
        # base64_string = data['bgasy'][1] # Extract the base64 string (second element in the list)
        # decoded_data = base64.b64decode(base64_string)         # Decode the base64 string
        # print(decoded_data)
        return json_data
    elif "text/javascript" in content_type or "application/javascript" in content_type:
        print("Handling Javascript data")
        return data.decode('utf-8')
    elif "text/css" in content_type:
        print("Handling CSS data")
        css_content = data.decode('utf-8')
        return css_content
    elif 'text/html' in content_type:
        print("Handling HTML data")
        return BeautifulSoup(data, 'html.parser')
    elif 'application/x-www-form-urlencoded' in content_type:
        print("Handling URL-encoded data")
        # Parse URL-encoded data
        from urllib.parse import parse_qs
        return parse_qs(data)
    elif 'text/plain' in content_type:
        print("Handling plain text data")
        # Handle plain text data
        return data.decode('utf-8')
    else:
        print("Not equipped to decode this datatype")
        return data


if __name__ == "__main__":
    start_processes()
    socketio.run(app, host='0.0.0.0', port=flask_port, debug=True, allow_unsafe_werkzeug=True )
