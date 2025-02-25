from mitmproxy import http, ctx
import json
import sqlite3  # Import SQLite

# Global variables
DATABASE_FILE = "traffic.db"  # Name of database file
interception_enabled = False
traffic_controller_instance = None  # Global variable


def toggle_interception():
    global interception_enabled
    interception_enabled = not interception_enabled
    print(f"interception_enabled current value -> {interception_enabled}")
    state = "enabled" if interception_enabled else "disabled"
    global traffic_controller_instance
    if interception_enabled:
        traffic_controller_instance.flow.resume()

    return state


class TrafficController:
    def __init__(self):
        global traffic_controller_instance  # Declare as global
        traffic_controller_instance = self
        # Initialize database connection
        try:
            self.conn = sqlite3.connect(DATABASE_FILE)
            self.cursor = self.conn.cursor()
            self.cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS traffic (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    flow_type TEXT NOT NULL,  -- 'request' or 'response'
                    url TEXT NOT NULL,
                    port TEXT NOT NULL,
                    method TEXT NOT NULL,
                    scheme TEXT,
                    http_version TEXT,
                    headers TEXT,
                    content TEXT,
                    trailers TEXT,
                    data TEXT,
                    is_modified INTEGER DEFAULT 0,  -- 0 for not modified, 1 for modified
                    interception INTEGER DEFAULT 0, -- 0 for not intercepted, 1 intercepted
                    flag TEXT
                )
                """
            )
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"Database error: {e}")

    def start(self):
        print("TrafficController addon [start] triggered ") #debug
        ctx.log.info(f"Proxy is listening on port {ctx.options.listen_port}")

    def request(self, flow: http.HTTPFlow) -> None:
        print("TrafficController addon [request] triggered ") # debug
        print(f"interception state is {interception_enabled}") # debug
        if interception_enabled:
            flow.intercept()
            # print(f"flow.request.get_content() is : {flow.request.get_content()}")
            print(f"flow.request.get_textt() is : {flow.request.get_text()}")
            print(f"flow.request.text is : {flow.request.text}")
            print(f"flow.request.headers is : {json.dumps(dict(flow.request.headers))}")

            request_data = {
                "url": flow.request.pretty_url,
                "port": flow.request.port,
                "method": flow.request.method,
                "scheme": flow.request.scheme,
                "http_version": flow.request.http_version,
                "headers": json.dumps(dict(flow.request.headers)),
                "content": flow.request.get_content().decode('utf-8') if flow.request.get_content() else '',
                "trailers": str(flow.request.trailers)
            }
            print(flow.request.method)  # debug
            request_data_string = json.dumps(request_data, indent=4)

            try:
                print(request_data)
                self.cursor.execute(
                    "INSERT INTO traffic (flow_type, url, port, method, scheme, http_version, headers, content, trailers, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    ("request",
                     flow.request.pretty_url,
                     request_data['port'],
                     request_data['method'],
                     request_data['scheme'],
                     request_data['http_version'],
                     request_data['headers'],
                     request_data['content'],
                     request_data['trailers'],
                     request_data_string)
                )

                print("trying to insert request into database")  # debug
                flow.request.id = self.cursor.lastrowid
                self.conn.commit()
                # ctx.log.info(
                #     f"Intercepted request to {flow.request.pretty_url} (ID: {flow.request.id})"
                # )
            except sqlite3.Error as e:
                print("sqllite error in  request")  # debug
                ctx.log.error(f"Database error during request: {e}")

    def response(self, flow: http.HTTPFlow) -> None:
        print("TrafficController addon [response] triggered ") #debug
        if interception_enabled:
            flow.intercept()
            # print(f"flow.request.get_content() is : {flow.request.get_content()}")
            # print(f"flow.request.get_textt() is : {flow.request.get_text()}")
            # print(f"flow.request.text is : {flow.request.text}")

            response_data = {
                "url": flow.response.pretty_url,
                "port": flow.response.port,
                "method": flow.response.method,
                "scheme": flow.response.scheme,
                "http_version": flow.response.http_version,
                "headers": str(dict(flow.response.headers)),
                "content": flow.response.get_content().decode('utf-8') if flow.response.get_content() else '',
                "trailers": str(flow.response.trailers),
            }
            print(flow.response.method)  # debug
            response_data_string = json.dumps(response_data, indent=4)

            try:
                print(response_data)
                self.cursor.execute(
                    "INSERT INTO traffic (flow_type, url, port, method, scheme, http_version, headers, content, trailers, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    ("response",
                     flow.request.pretty_url,
                     response_data['port'],
                     response_data['method'],
                     response_data['scheme'],
                     response_data['http_version'],
                     response_data['headers'],
                     response_data['content'],
                     response_data['trailers'],
                     response_data_string)
                )

                print("trying to insert request into database")  # debug
                flow.request.id = self.cursor.lastrowid
                self.conn.commit()
                # ctx.log.info(
                #     f"Intercepted request to {flow.request.pretty_url} (ID: {flow.request.id})"
                # )
            except sqlite3.Error as e:
                print("sqllite error in  request")  # debug
                ctx.log.error(f"Database error during request: {e}")


addons = [TrafficController()]
