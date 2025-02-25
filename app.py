from flask import Flask, render_template, request, jsonify
import subprocess
import os
import sqlite3
import json  # Import the json module
from broxy import launch_broxy
from proxy import toggle_interception
import time

app = Flask(__name__)

# Configurations--------------------------------
DATABASE_FILE = "traffic.db"  # Database file (must be in same folder as in proxy.py)
mitm_port = "8080"
flask_port = '5050'
# ----------------------------------------------

# Run Proxy and Browser Python script

if os.path.exists("traffic.db"):
    os.remove("traffic.db")
    print("refreshed traffic.db")
else:
    print("No prior traffic.db")

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
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, flow_type, url FROM traffic ORDER BY id DESC")  # Display latest requests
    traffic_data = cursor.fetchall()
    conn.close()
    return render_template("index.html", traffic=traffic_data, mitm_port=mitm_port)


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
