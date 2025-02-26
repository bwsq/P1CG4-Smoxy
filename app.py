from flask import Flask, render_template, request
import subprocess
import os
import sqlite3
import json  # Import the json module
from broxy import launch_broxy
import time
from config import DATABASE_FILE, mitm_port, flask_port, toggle_interception, get_interception_enabled, stringToBoolean

app = Flask(__name__)

# Run Proxy and Browser Python script

if os.path.exists(DATABASE_FILE):
    os.remove(DATABASE_FILE)
    print(f"refreshed {DATABASE_FILE}")
else:
    print(f"No prior {DATABASE_FILE}")

# Instantiate Intercept and Resume flag values
with open('intercept.txt', 'w') as file:
    file.write('False')
with open('resume.txt', 'w') as file:
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
            status_code INT,
            reason TEXT,
            port TEXT,
            method TEXT,
            scheme TEXT,
            http_version TEXT,
            headers TEXT,
            content BLOB,
            trailers TEXT,
            is_modified INTEGER DEFAULT 0,  -- 0 for not modified, 1 for modified
            intercepted INTEGER DEFAULT 0, -- 0 for not intercepted, 1 intercepted
            flag TEXT
        )
        """
    )
    conn.commit()
    conn.close()
except sqlite3.Error as e:
    print(f"Database error: {e}")

# Runs MITMPROXY Verbose version, uncomment if you want to use this version then comment the one below
# processes = (["mitmdump", "-p", mitm_port, "-s", "proxy.py"],
#              ["python", "broxy.py"])

processes = (["mitmdump", "-p", mitm_port, "--set", "flow_detail=0", "-s", "proxy.py"],
             ["python", "broxy.py"])


def start_processes():
    if not os.environ.get('WERKZEUG_RUN_MAIN'):  # Prevents duplicate execution caused by flask debug mode
        for process in processes:
            subprocess.Popen(process)
            time.sleep(2)  # ensure mitmproxy running
            print(f"[!] {process[-1]} running\n")


# FLASK STUFF - Control Panel
@app.route("/")
def home():
    # conn = sqlite3.connect(DATABASE_FILE)
    # cursor = conn.cursor()
    # cursor.execute(f"SELECT id, flow_type, url FROM {TABLE} ORDER BY id DESC")  # Display latest requests
    # traffic_data = cursor.fetchall()
    # conn.close()
    interception_enabled = stringToBoolean(get_interception_enabled())
    print(f"interception_enabled in App.py first one {type(interception_enabled)} {interception_enabled}")
    if interception_enabled:
        intercept_state = 'Enabled'
    else:
        intercept_state = 'Disabled'
        print(f"STUPID THING WONT WORK {intercept_state} ")
    return render_template("index.html",
                           mitm_port=mitm_port,
                           interception_enabled=intercept_state
                           )


@app.route("/open_browser", methods=['GET', 'POST'])
def open_browser():
    print("Launching a browser instance")
    launch_broxy()
    return "Browser opened"


@app.route("/toggle-intercept", methods=['POST'])
def toggle_intercept():
    print("Toggling intercept")
    state = toggle_interception()  # Call the function from proxy.py, returns enabled or disabled
    print(f"State Change : {state}")
    return state  # Return the state of the variable


# @app.route("/forward", methods=['POST'])
# def toggle_intercept():
#     print("Toggling intercept")
#     state = toggle_interception()  # Call the function from proxy.py, returns enabled or disabled
#     print(f"State Change : {state}")
#     return state  # Return the state of the variable

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


if __name__ == "__main__":
    start_processes()
    app.run(host='0.0.0.0', port=flask_port, debug=True)
