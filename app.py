from flask import Flask, render_template, request, send_from_directory
import subprocess
import os
import sqlite3
import json
import time
from anytree import Node, RenderTree
from urllib.parse import urlparse
from config import DATABASE_FILE, mitm_port, flask_port, toggle_interception, get_interception_enabled, stringToBoolean
from broxy import launch_broxy

app = Flask(__name__)

INTERCEPTED_DIR = 'intercepted_traffic'

if not os.path.exists(INTERCEPTED_DIR):
    os.makedirs(INTERCEPTED_DIR)

if os.path.exists(DATABASE_FILE):
    os.remove(DATABASE_FILE)
    print(f"refreshed {DATABASE_FILE}")
else:
    print(f"No prior {DATABASE_FILE}")

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
            flow_type TEXT,
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
            is_modified INTEGER DEFAULT 0,
            intercepted INTEGER DEFAULT 0,
            flag TEXT
        )
        """
    )
    conn.commit()
    conn.close()
except sqlite3.Error as e:
    print(f"Database error: {e}")

processes = (
    ["mitmdump", "-p", mitm_port, "--set", "flow_detail=0", "-s", "proxy.py"],
    ["python", "broxy.py"]
)

def start_processes():
    """Starts the proxy and browser processes."""
    if not os.environ.get('WERKZEUG_RUN_MAIN'):
        for process in processes:
            subprocess.Popen(process)
            time.sleep(2)
            print(f"[!] {process[-1]} running\n")

@app.route("/")
def home():
    interception_enabled = stringToBoolean(get_interception_enabled())
    intercept_state = 'Enabled' if interception_enabled else 'Disabled'
    return render_template("index.html", mitm_port=mitm_port, interception_enabled=intercept_state)

@app.route("/open_browser", methods=['GET', 'POST'])
def open_browser():
    print("Launching a browser instance")
    launch_broxy()
    return "Browser opened"

@app.route("/toggle-intercept", methods=['POST'])
def toggle_intercept():
    print("Toggling intercept")
    state = toggle_interception()
    print(f"State Change: {state}")

    if state == "Enabled":
        with open("intercepted_urls.txt", "a") as url_file:
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute("SELECT url FROM traffic WHERE intercepted = 0")
            urls = cursor.fetchall()
            for url in urls:
                url_file.write(url[0] + "\n")
                cursor.execute("UPDATE traffic SET intercepted = 1 WHERE url = ?", (url[0],))
            conn.commit()
            conn.close()
        print("URLs stored in intercepted_urls.txt")

    return state

@app.route("/traffic/<int:traffic_id>", methods=['GET', 'POST'])
def view_traffic(traffic_id):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()

    if request.method == 'POST':
        modified_data = request.form['traffic_data']
        cursor.execute("UPDATE traffic SET data = ?, is_modified = 1 WHERE id = ?", (modified_data, traffic_id))
        conn.commit()
        with open("resume.txt", "w") as f:
            f.write("resume")
        conn.close()
        return "Traffic modified and resumed"

    cursor.execute("SELECT flow_type, url, content FROM traffic WHERE id = ?", (traffic_id,))
    traffic = cursor.fetchone()
    conn.close()

    if traffic:
        flow_type, url, data = traffic
        try:
            data_pretty = json.dumps(json.loads(data), indent=4)
        except json.JSONDecodeError:
            data_pretty = data

        return render_template("view_traffic.html", traffic_id=traffic_id, flow_type=flow_type, url=url,
                               traffic_data=data_pretty)
    else:
        return "Traffic not found"

def build_tree(urls):
    root = Node("Intercepted URLs")
    domain_nodes = {}

    for url in urls:
        parsed = urlparse(url.strip())
        domain = parsed.netloc
        path_parts = parsed.path.strip("/").split("/") if parsed.path else []

        if domain not in domain_nodes:
            domain_nodes[domain] = Node(domain, parent=root)

        parent_node = domain_nodes[domain]
        for part in path_parts:
            child = next((node for node in parent_node.children if node.name == part), None)
            if not child:
                child = Node(part, parent=parent_node)
            parent_node = child

    return root

@app.route("/intercepted-urls")
def show_intercepted_urls():
    try:
        with open("intercepted_urls.txt", "r") as file:
            urls = file.readlines()
    except FileNotFoundError:
        urls = []

    tree_root = build_tree(urls)
    tree_output = "\n".join(f"{pre}{node.name}" for pre, _, node in RenderTree(tree_root))

    return f"<pre>{tree_output}</pre>"

if __name__ == "__main__":
    start_processes()
    app.run(host='0.0.0.0', port=flask_port, debug=True)
