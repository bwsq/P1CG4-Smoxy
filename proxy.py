import time
import os
import json
import sqlite3
from mitmproxy import http, ctx
from config import DATABASE_FILE, set_resume_signal, get_interception_enabled, get_resume_signal, stringToBoolean

# Define the directory for intercepted traffic
INTERCEPTED_DIR = "intercepted_traffic"

class TrafficController:
    def __init__(self):
        self.flow = None
        os.makedirs(INTERCEPTED_DIR, exist_ok=True)  # Create the directory if it doesn't exist

    def saveToDB(self, flowtype, data, intercept):
        try:
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()

            if flowtype == 'request':
                cursor.execute(
                    "INSERT INTO traffic (flow_type, url, port, method, scheme, http_version, headers, content, trailers, intercepted) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (flowtype, data['url'], data['port'], data['method'], data['scheme'], data['http_version'],
                     data['headers'], data['content'], data['trailers'], intercept)
                )
            elif flowtype == 'response':
                cursor.execute(
                    "INSERT INTO traffic (flow_type, url, status_code, reason, http_version, headers, content, trailers, intercepted) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (flowtype, data['url'], data['status_code'], data['reason'], data['http_version'],
                     data['headers'], data['content'], data['trailers'], intercept)
                )

            conn.commit()
            conn.close()
            return 1  # Success

        except sqlite3.Error as e:
            ctx.log.error(f"Database error: {e}")
            return 0

    def saveToFile(self, filename, content):
        """Save intercepted request/response to a file"""
        filepath = os.path.join(INTERCEPTED_DIR, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        self.updateDirectoryTree()

    def updateDirectoryTree(self):
        """Generate directory.html with clickable links to intercepted files"""
        base_url = "http://192.168.32.130:5050/intercepted_traffic/"
        tree_html = "<html><head><title>Intercepted Traffic</title></head><body>"
        tree_html += "<h2>Intercepted Traffic Directory</h2><ul>"

        for filename in sorted(os.listdir(INTERCEPTED_DIR)):
            if filename != "directory.html":
                tree_html += f'<li><a href="{base_url}{filename}" target="_blank">{filename}</a></li>'

        tree_html += "</ul></body></html>"

        with open(os.path.join(INTERCEPTED_DIR, "directory.html"), "w", encoding="utf-8") as f:
            f.write(tree_html)

        print("Directory tree updated: intercepted_traffic/directory.html")

    def request(self, flow: http.HTTPFlow) -> None:
        """Handle intercepted HTTP request"""
        interception_enabled = stringToBoolean(get_interception_enabled())

        self.flow = flow
        print("\nTrafficController addon [request] triggered")  # Debug

        request_data = {
            "url": flow.request.pretty_url,
            "port": flow.request.port,
            "method": flow.request.method,
            "scheme": flow.request.scheme,
            "http_version": flow.request.http_version,
            "headers": json.dumps(dict(flow.request.headers)),
            "content": flow.request.get_content().decode("utf-8", "ignore"),
            "trailers": str(flow.request.trailers)
        }

        # Save request to file
        filename = f"request_{int(time.time())}.txt"
        self.saveToFile(filename, json.dumps(request_data, indent=4))

        if interception_enabled:
            set_resume_signal(False)
            self.saveToDB(flowtype="request", data=request_data, intercept=1)
            flow.intercept()
            self.waitForResumeSignal()
            flow.resume()
        else:
            self.saveToDB(flowtype="request", data=request_data, intercept=0)
            flow.resume()

    def response(self, flow: http.HTTPFlow) -> None:
        """Handle intercepted HTTP response"""
        interception_enabled = stringToBoolean(get_interception_enabled())

        response_data = {
            "url": flow.request.pretty_url,
            "status_code": flow.response.status_code,
            "reason": flow.response.reason,
            "http_version": flow.response.http_version,
            "headers": json.dumps(dict(flow.response.headers)),
            "content": flow.response.get_content().decode("utf-8", "ignore"),
            "trailers": str(flow.response.trailers)
        }

        # Save response to file
        filename = f"response_{int(time.time())}.txt"
        self.saveToFile(filename, json.dumps(response_data, indent=4))

        if interception_enabled:
            set_resume_signal(False)
            self.saveToDB(flowtype="response", data=response_data, intercept=1)
            flow.intercept()
            self.waitForResumeSignal()
            flow.resume()
        else:
            self.saveToDB(flowtype="response", data=response_data, intercept=0)

    def waitForResumeSignal(self):
        resume_signal = stringToBoolean(get_resume_signal())
        while not resume_signal:
            time.sleep(1)
            resume_signal = stringToBoolean(get_resume_signal())

        print("Resume Signal Toggled")
        set_resume_signal(False)

addons = [TrafficController()]
