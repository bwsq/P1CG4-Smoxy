import time

from mitmproxy import http, ctx
import json, requests
import sqlite3  # Import SQLite
from config import (DATABASE_FILE, set_resume_signal, get_interception_enabled,
                    get_resume_signal, stringToBoolean, set_drop_signal, get_drop_signal, flask_url)


class TrafficController:
    def __init__(self):
        self.flow = None
        self.conn = None
        self.cursor = None
        self.last_row_id = None
        # Initialize database connection
        # try:
        #     self.conn = sqlite3.connect(DATABASE_FILE)
        #     self.cursor = self.conn.cursor()
        # except sqlite3.Error as e:
        #     print(f"Database error: {e}")

    def saveToDB(self, flowtype, data, intercept):

        try:
            self.conn = sqlite3.connect(DATABASE_FILE)
            self.cursor = self.conn.cursor()

            # Request Body (if present)
            if self.flow.request.content:
                body = self.flow.request.content.decode("utf-8", errors="ignore")
            else:
                body = None

            if flowtype == 'request':
                self.cursor.execute(
                    "INSERT INTO traffic (flow_type, url, path, port, method, scheme, http_version, headers, content, trailers, intercepted) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (flowtype,
                     self.flow.request.pretty_url,
                     data['path'],
                     data['port'],
                     data['method'],
                     data['scheme'],
                     data['http_version'],
                     data['headers'],
                     data['content'],
                     data['trailers'],
                     intercept
                     )
                )
            elif flowtype == 'response':
                self.cursor.execute(
                    "INSERT INTO traffic (flow_type, url, path, status_code, reason, http_version, headers, content, trailers, intercepted) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (flowtype,
                     data['url'],
                     data['path'],
                     data['status_code'],
                     data['reason'],
                     data['http_version'],
                     data['headers'],
                     data['content'],
                     data['trailers'],
                     intercept
                     )
                )

            self.last_row_id = self.cursor.lastrowid

            self.conn.commit()
            self.conn.close()
            return 1  # success

        except sqlite3.Error as e:
            print("sqllite error in  request")  # debug
            ctx.log.error(f"Database error during request: {e}")
            return 0

    def updateToDBbyID(self, field, value, id):
        try:
            self.conn = sqlite3.connect(DATABASE_FILE)
            self.cursor = self.conn.cursor()

            # Prepare the SQL command
            command = f"UPDATE traffic SET {field} = ? WHERE id = ?"

            # Execute the command with parameters
            self.cursor.execute(command, (value, id))

            self.conn.commit()
            self.conn.close()
            print(f'Updated ID {id} : {field} = {value}')
            return 1
        except sqlite3.Error as e:
            print("sqllite error in  request")  # debug
            ctx.log.error(f"Database error during request: {e}")
            return 0

    def request(self, flow: http.HTTPFlow) -> None:
        interception_enabled = stringToBoolean(get_interception_enabled())

        self.flow = flow
        print("\nTrafficController addon [request] triggered")  # debug
        print(f"interception_enabled value is {interception_enabled}")  # debug


        request_data = {
            "url": flow.request.pretty_url,
            "path": flow.request.path,
            "port": flow.request.port,
            "method": flow.request.method,
            "scheme": flow.request.scheme,
            "http_version": flow.request.http_version,
            "headers": json.dumps(dict(flow.request.headers)),
            "content": flow.request.get_content(),
            "trailers": str(flow.request.trailers)
        }

        # Ignore Chrome auto calls to optimizationguide and safebrowsing
        if "optimizationguide-pa.googleapis.com" in flow.request.url:
            flow.resume()
            print("request to optimizationguide-pa.googleapis.com skipped")
        elif 'safebrowsingohttpgateway.googleapis.com' in flow.request.url:
            flow.resume()
            print("request to safebrowsingohttpgateway.googleapis.com skipped")
        elif interception_enabled:
            set_resume_signal(False);
            set_drop_signal(False);
            print(f"Request Intercepted, interception_enabled is {interception_enabled}")  # debug
            self.saveToDB(flowtype="request", data=request_data, intercept=1)
            flow.intercept()
            self.callToFlask('response')
            self.waitForResumeSignal()
            print(f"Request Resumed")  # debug
            drop_signal = get_drop_signal()
            if drop_signal == 'True':
                if flow.killable:
                    try:
                        flow.kill()
                        self.updateToDBbyID('action', 'dropped', self.last_row_id)
                    except Exception as e:
                        print(f"failed to kill flow : {e}")
            else:
                self.updateToDBbyID('action', 'forwarded', self.last_row_id)
                flow.resume()
        else:
            self.saveToDB(flowtype="request", data=request_data, intercept=0)
            self.updateToDBbyID('action', 'forwarded', self.last_row_id)
            flow.resume()

    def response(self, flow: http.HTTPFlow) -> None:
        interception_enabled = stringToBoolean(get_interception_enabled())
        print("\nTrafficController addon [response] triggered ")  # debug

        response_data = {
            "url": flow.request.url,
            "path": flow.request.path,
            "status_code": flow.response.status_code,
            "reason": flow.response.reason,
            "http_version": flow.response.http_version,
            "headers": str(dict(flow.response.headers)),
            "content": flow.response.get_content(),
            "trailers": str(flow.response.trailers),
        }
        # response_data_string = json.dumps(response_data, indent=4)
        if "optimizationguide-pa.googleapis.com" in flow.request.url:
            flow.resume()
            print("response from optimizationguide-pa.googleapis.com skipped")
        elif 'safebrowsingohttpgateway.googleapis.com' in flow.request.url:
            flow.resume()
            print("response from safebrowsingohttpgateway.googleapis.com skipped")
        elif interception_enabled:
            set_resume_signal(False)
            set_drop_signal(False);
            print(f"Response Intercepted, interception_enabled is {interception_enabled}")  # debug
            self.saveToDB(flowtype="response", data=response_data, intercept=1)
            flow.intercept()
            self.callToFlask('response')
            self.waitForResumeSignal()
            print(f"Request Resumed")  # debug
            drop_signal = get_drop_signal()

            if drop_signal == 'True':
                if flow.killable:
                    try:
                        flow.kill()
                        self.updateToDBbyID('action', 'dropped', self.last_row_id)
                    except Exception as e:
                        print(f"failed to kill flow : {e}")
            else:
                self.updateToDBbyID('action', 'forwarded', self.last_row_id)
                flow.resume()
        else:
            self.saveToDB(flowtype="response", data=response_data, intercept=0)
            self.updateToDBbyID('action', 'forwarded', self.last_row_id)
            flow.resume()

    def waitForResumeSignal(self):
        resume_signal = stringToBoolean(get_resume_signal())
        while not resume_signal:  # wait for resume signal be changed
            time.sleep(1)
            resume_signal = stringToBoolean(get_resume_signal())
        print("Resume Signal Toggled")  # debug
        set_resume_signal(False)  # reset resume signal
        return 0

    def callToFlask(self, type):
        global flask_url
        url = f"{flask_url}/incoming-flow"  # Call to flask
        payload = {
            "type": type  # request or response
        }
        response = requests.post(url, json=payload)
        # Print the response from Flask
        if response.status_code == 200:
            print(f"Success CallToFlask")
        else:
            print(f"Error CallToFlask")


addons = [TrafficController()]
