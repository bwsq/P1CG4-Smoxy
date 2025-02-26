import time

from mitmproxy import http, ctx
import json
import sqlite3  # Import SQLite
from config import DATABASE_FILE,  set_resume_signal, get_interception_enabled, get_resume_signal, stringToBoolean

class TrafficController:
    def __init__(self):
        self.flow = None
        self.conn = None
        self.cursor = None
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
            if flowtype == 'request':
                self.cursor.execute(
                    "INSERT INTO traffic (flow_type, url, port, method, scheme, http_version, headers, content, trailers, intercepted) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (flowtype,
                     self.flow.request.pretty_url,
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
                    "INSERT INTO traffic (flow_type, url, status_code, reason, http_version, headers, content, trailers, intercepted) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (flowtype,
                     data['url'],
                     data['status_code'],
                     data['reason'],
                     data['http_version'],
                     data['headers'],
                     data['content'],
                     data['trailers'],
                     intercept
                     )
                )

            self.flow.request.id = self.cursor.lastrowid
            print(f" Save successful. Entry ID : {self.flow.request.id}")
            self.conn.commit()
            self.conn.close()
            return 1  # success

        except sqlite3.Error as e:
            print("sqllite error in  request")  # debug
            ctx.log.error(f"Database error during request: {e}")
            return 0

    def request(self, flow: http.HTTPFlow) -> None:
        interception_enabled = stringToBoolean(get_interception_enabled())

        self.flow = flow
        print("\nTrafficController addon [request] triggered")  # debug
        print(f"interception_enabled value is {interception_enabled}")  # debug

        # print(f"flow.request.get_content() is : {flow.request.get_content()}")
        # print(f"flow.request.get_textt() is : {flow.request.get_text()}")
        # print(f"flow.request.text is : {flow.request.text}")
        # print(f"flow.request.headers is : {json.dumps(dict(flow.request.headers))}")
        # print(f"server connection is {flow.server_conn.address[0]}")
        request_data = {
            "url": flow.request.pretty_url,
            "port": flow.request.port,
            "method": flow.request.method,
            "scheme": flow.request.scheme,
            "http_version": flow.request.http_version,
            "headers": json.dumps(dict(flow.request.headers)),
            "content": flow.request.get_content(),
            # "content": flow.request.get_content().decode('utf-8') if flow.request.get_content() else '',
            "trailers": str(flow.request.trailers)
        }
        # request_data_string = json.dumps(request_data, indent=4)

        # Ignore Chrome auto calls to optimizationguide and safebrowsing
        if "optimizationguide-pa.googleapis.com" in flow.request.url:
            flow.resume()
            print("request to optimizationguide-pa.googleapis.com skipped")
        elif 'safebrowsingohttpgateway.googleapis.com' in flow.request.url:
            flow.resume()
            print("request to safebrowsingohttpgateway.googleapis.com skipped")
        elif interception_enabled:
            set_resume_signal(False);
            print(f"Request Intercepted, interception_enabled is {interception_enabled}")  # debug
            self.saveToDB(flowtype="request", data=request_data, intercept=1)
            flow.intercept()
            self.waitForResumeSignal()
            print(f"Request Resumed")  # debug
            flow.resume()
        else:
            self.saveToDB(flowtype="request", data=request_data, intercept=0)
            flow.resume()

    def response(self, flow: http.HTTPFlow) -> None:
        interception_enabled = stringToBoolean(get_interception_enabled())
        print("\nTrafficController addon [response] triggered ")  # debug
        # print(f"flow.request.get_content() is : {flow.request.get_content()}")
        # print(f"flow.request.get_text() is : {flow.request.get_text()}")
        # print(f"flow.request.text is : {flow.request.text}")
        # https: // example.com / favicon.ico

        response_data = {
            "url": flow.request.url,
            "status_code": flow.response.status_code,
            "reason": flow.response.reason,
            "http_version": flow.response.http_version,
            "headers": str(dict(flow.response.headers)),
            "content": flow.response.get_content(),
            # "content": flow.response.get_content().decode('utf-8') if flow.response.get_content() else '',
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
            print(f"Response Intercepted, interception_enabled is {interception_enabled}")  # debug
            self.saveToDB(flowtype="response", data=response_data, intercept=1)
            flow.intercept()
            self.waitForResumeSignal()
            print(f"Request Resumed")  # debug
            flow.resume()
        else:
            self.saveToDB(flowtype="response", data=response_data, intercept=0)


    def waitForResumeSignal(self):
        resume_signal = stringToBoolean(get_resume_signal())
        while not resume_signal:  # wait for resume signal be changed
            time.sleep(1)
            resume_signal = stringToBoolean(get_resume_signal())

        print("Resume Signal Toggled")  # debug
        set_resume_signal(False)   # reset resume signal
        return 0


addons = [TrafficController()]
