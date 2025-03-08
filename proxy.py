import time
import re
import json
import requests
import sqlite3
from mitmproxy import http, ctx
from config import (
    DATABASE_FILE, set_resume_signal, get_interception_enabled,
    get_resume_signal, stringToBoolean, set_drop_signal, get_drop_signal,
    flask_url, get_modified, set_modified
)

# Regex to extract content safely
pattern = r'"?content"?\s*:\s*"(.*?)"'


class TrafficController:
    def __init__(self):
        self.flow = None
        self.conn = None
        self.cursor = None
        self.last_row_id = None

    def saveToDB(self, flowtype, data, intercept):
        """Save request or response data to SQLite database."""
        try:
            self.conn = sqlite3.connect(DATABASE_FILE)
            self.cursor = self.conn.cursor()

            if flowtype == 'request':
                self.cursor.execute(
                    "INSERT INTO traffic (flow_type, url, path, port, method, scheme, http_version, headers, content, trailers, intercepted) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (flowtype, self.flow.request.pretty_url, data['path'], data['port'],
                     data['method'], data['scheme'], data['http_version'], data['headers'],
                     data['content'], data['trailers'], intercept)
                )
            elif flowtype == 'response':
                self.cursor.execute(
                    "INSERT INTO traffic (flow_type, url, path, status_code, reason, http_version, headers, content, trailers, intercepted) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (flowtype, data['url'], data['path'], data['status_code'], data['reason'],
                     data['http_version'], data['headers'], data['content'], data['trailers'], intercept)
                )

            self.last_row_id = self.cursor.lastrowid
            self.conn.commit()
            self.conn.close()
        except sqlite3.Error as e:
            ctx.log.error(f"Database error: {e}")

    def updateToDBbyID(self, field, value, id):
        """Update a database entry by ID."""
        try:
            self.conn = sqlite3.connect(DATABASE_FILE)
            self.cursor = self.conn.cursor()
            self.cursor.execute(f"UPDATE traffic SET {field} = ? WHERE id = ?", (value, id))
            self.conn.commit()
            self.conn.close()
        except sqlite3.Error as e:
            ctx.log.error(f"Database error during update: {e}")

    # def processModifiedContent(self):
    #     modified_content = get_modified()
    #     print(f"Raw modified content (directly from get_modified()): {repr(modified_content)}")

    #     if not modified_content.strip():
    #         print("No modified content received — skipping modification.")
    #         return None, None

    #     data, content = self.extractContent(modified_content)

    #     print(f"Data to be parsed: {repr(data)}")
    #     print(f"Extracted content: {repr(content)}")

    #     # DONE UNTIL ABOVE HERE
    #     # Error decoding JSON for traffic_dict: Expecting property name enclosed in double quotes: line 32 column 1 (char 1445)

    #     if not data.strip():
    #         print("No data to parse — skipping modification.")
    #         return None, None

    #     traffic_dict = None
    #     unpacked_content = None  # Ensure unpacked_content exists no matter what

    #     try:
    #         traffic_dict = json.loads(data)
    #         print(f"Parsed traffic_dict: {traffic_dict}")
    #     except json.JSONDecodeError as e:
    #         print(f"Error decoding JSON for traffic_dict: {e}") # ERROR HERE WHEN X-WWW TO HMTL RETURN
    #         print(f"Problematic JSON data: {repr(data)}")
    #         return None, None

    #     if content:
    #         try:
    #             unpacked_content = json.loads(content)
    #             print(f"Parsed unpacked_content: {unpacked_content}")
    #         except json.JSONDecodeError:
    #             unpacked_content = content  # Fallback to plain string if not JSON

    #     return traffic_dict, unpacked_content

    def processModifiedContent(self):
        modified_content = get_modified()
        print("DEBUGGING - ", type(modified_content))
        print(f"Raw modified content (directly from get_modified()): {repr(modified_content)}")

        if not modified_content.strip():
            print("No modified content received — skipping modification.")
            return None, None

        # data, content = self.extractContent(modified_content)

        # print(f"Data to be parsed: {repr(data)}")
        # print(f"Extracted content: {repr(content)}")

        # if not data.strip():
        #     print("No data to parse — skipping modification.")
        #     return None, None

        traffic_dict = None
        unpacked_content = None  # Ensure unpacked_content exists no matter what

        print("DEBUGGING222222 - ", type(modified_content))

        try:
            traffic_dict = json.loads(modified_content)
            print(f"Parsed traffic_dict: {traffic_dict}")
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON for traffic_dict: {e}") # current error
            print(f"Problematic JSON data: {repr(modified_content)}")
            return None, None
        
        # Directly extract content from the parsed dict
        content = traffic_dict.get('content', '')
        print(f"Extracted content from traffic_dict: {repr(content)}")

        content_type = traffic_dict.get("headers", {}).get("Content-Type", "").lower()

        if content:
            # Process content based on detected Content-Type
            if 'application/json' in content_type:
                try:
                    unpacked_content = json.loads(content)
                    print(f"Parsed JSON content: {unpacked_content}")
                except json.JSONDecodeError:
                    print("Content is invalid JSON, keeping as raw string.")
                    unpacked_content = content

            elif 'application/x-www-form-urlencoded' in content_type:
                try:
                    from urllib.parse import parse_qs
                    parsed_content = parse_qs(content)
                    print(f"Parsed Form content: {parsed_content}")
                    unpacked_content = content  # Optionally keep raw if needed
                except Exception as e:
                    print(f"Failed to parse x-www-form-urlencoded content: {e}")
                    unpacked_content = content

            elif 'text/html' in content_type or 'text/plain' in content_type:
                print("Content is HTML or plain text, keeping as raw string.")
                unpacked_content = content

            elif 'application/xml' in content_type:
                print("Content is XML, keeping as raw string (for now).")
                unpacked_content = content

            else:
                print(f"Unhandled content type '{content_type}', treating as raw string.")
                unpacked_content = content

        return traffic_dict, unpacked_content


    def applyHeaders(self, flow_headers, headers_data):
        """Safely apply headers to a request or response."""
        if isinstance(headers_data, str):
            headers_data = json.loads(headers_data)

        if isinstance(headers_data, dict):
            flow_headers.clear()
            for key, value in headers_data.items():
                flow_headers[key] = value
        else:
            print("Headers data is invalid!")

    def request(self, flow: http.HTTPFlow):
        """Intercept and modify HTTP requests."""
        interception_enabled = stringToBoolean(get_interception_enabled())
        self.flow = flow

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

        if interception_enabled:
            set_resume_signal(False)
            set_drop_signal(False)
            self.saveToDB("request", request_data, intercept=1)
            flow.intercept()
            self.callToFlask('request')
            self.waitForResumeSignal()

            if stringToBoolean(get_drop_signal()):
                if flow.killable:
                    flow.kill()
                    self.updateToDBbyID('action', 'dropped', self.last_row_id)
            else:
                traffic_dict, unpacked_content = self.processModifiedContent()

                if traffic_dict:
                    for key in ['host', 'port', 'method', 'scheme', 'path', 'http_version']:
                        if key in traffic_dict:
                            setattr(flow.request, key, traffic_dict[key])

                    if 'headers' in traffic_dict:
                        self.applyHeaders(flow.request.headers, traffic_dict['headers'])

                if isinstance(unpacked_content, str):
                    flow.request.content = unpacked_content.encode('utf-8')

                self.updateToDBbyID('is_modified', 1, self.last_row_id)
                self.updateToDBbyID('action', 'forwarded', self.last_row_id)
                flow.resume()
        else:
            self.saveToDB("request", request_data, intercept=0)
            self.updateToDBbyID('action', 'forwarded', self.last_row_id)
            flow.resume()

    def response(self, flow: http.HTTPFlow):
        """Intercept and modify HTTP responses."""
        interception_enabled = stringToBoolean(get_interception_enabled())

        response_data = {
            "url": flow.request.url,
            "path": flow.request.path,
            "status_code": flow.response.status_code,
            "reason": flow.response.reason,
            "http_version": flow.response.http_version,
            "headers": json.dumps(dict(flow.response.headers)),
            "content": flow.response.get_content(),
            "trailers": str(flow.response.trailers),
        }

        if interception_enabled:
            set_resume_signal(False)
            set_drop_signal(False)
            self.saveToDB("response", response_data, intercept=1)
            flow.intercept()
            self.callToFlask('response')
            self.waitForResumeSignal()

            if stringToBoolean(get_drop_signal()):
                if flow.killable:
                    flow.kill()
                    self.updateToDBbyID('action', 'dropped', self.last_row_id)
            else:
                traffic_dict, unpacked_content = self.processModifiedContent()

                if traffic_dict:
                    for key in ['status_code', 'reason', 'http_version']:
                        if key in traffic_dict:
                            setattr(flow.response, key, traffic_dict[key])

                    if 'headers' in traffic_dict:
                        self.applyHeaders(flow.response.headers, traffic_dict['headers'])

                if isinstance(unpacked_content, str):
                    flow.response.content = unpacked_content.encode('utf-8')

                self.updateToDBbyID('is_modified', 1, self.last_row_id)
                self.updateToDBbyID('action', 'forwarded', self.last_row_id)
                flow.resume()
        else:
            self.saveToDB("response", response_data, intercept=0)
            self.updateToDBbyID('action', 'forwarded', self.last_row_id)
            flow.resume()

    def extractContent(self, input_string):
        """Extract content safely from modified JSON."""
        match = re.search(pattern, input_string, re.DOTALL)
        return re.sub(pattern, '', input_string, flags=re.DOTALL), match.group(1) if match else None

    def waitForResumeSignal(self):
        """Wait until the resume signal is toggled."""
        while not stringToBoolean(get_resume_signal()):
            time.sleep(1)
        set_resume_signal(False)

    def callToFlask(self, req_type):
        """Send intercepted request/response to Flask."""
        requests.post(f"{flask_url}/incoming-flow", json={"type": req_type})


addons = [TrafficController()]