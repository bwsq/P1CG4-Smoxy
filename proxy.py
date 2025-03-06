import time
import re
from mitmproxy import http, ctx
import json, requests, ast
import sqlite3  # Import SQLite
from config import (DATABASE_FILE, set_resume_signal, get_interception_enabled,
                    get_resume_signal, stringToBoolean, set_drop_signal, get_drop_signal, flask_url,
                    get_modified, set_modified)

pattern = r'"?content"?\s*":\s*"(.*?)"'
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
            self.callToFlask('request')
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
                # Handle Modified, Parse, Resume, Reset Modified
                unpacked_content = None
                modified_content = get_modified()
                modified_content = modified_content.replace("'", '"')
                modified_content = modified_content.replace('null', 'None')

                if modified_content:
                    print(modified_content)
                    print(type(modified_content))
                    traffic_dict = None
                    data, content = self.extractContent(modified_content)
                    try:
                        # Parse the JSON string into a Python dictionary
                        traffic_dict = ast.literal_eval(data)
                    except (ValueError, SyntaxError) as e:
                        traffic_dict = None
                        print(f"Error with ast decoding {e}")
                    except Exception as e:
                        # Catch any other exceptions
                        print(f"Unexpected error: {e}")
                        traffic_dict = None

                    if content:
                        try:
                            unpacked_content = ast.literal_eval(content)
                        except (ValueError, SyntaxError) as e:
                            unpacked_content = None
                            print(f"Error with ast decoding {e}")
                        except Exception as e:
                            # Catch any other exceptions
                            print(f"Unexpected error: {e}")
                            unpacked_content = None

                    if traffic_dict:

                        # Handle HOST
                        host = traffic_dict.get('host')
                        if host:
                            flow.request.host = host
                            print('Inserted Host')  # DEBUG
                        # Handle Port
                        port = traffic_dict.get('port')
                        if port:
                            flow.request.port = port
                            print('Inserted Port')  # DEBUG
                        # Handle method
                        method = traffic_dict.get('method')
                        if method:
                            flow.request.method = method
                            print('Inserted Method')  # DEBUG
                        # Handle scheme
                        scheme = traffic_dict.get('scheme')
                        if scheme:
                            flow.request.scheme = scheme
                            print('Inserted scheme')  # DEBUG
                        # Handle authority
                        authority = traffic_dict.get('authority')
                        if authority:
                            flow.request.authority = authority
                            print('Inserted authority')  # DEBUG
                        # Handle path
                        path = traffic_dict.get('path')
                        if path:
                            flow.request.path = path
                            print('Inserted path')  # DEBUG
                        # Handle HTTP
                        http_version = traffic_dict.get('http_version')
                        if http_version:
                            flow.request.http_version = http_version
                            print('Inserted http_version')  # DEBUG
                        # Handle headers
                        headers = traffic_dict.get('headers')
                        print(type(headers))
                        if headers:
                            for key in headers:
                                try:
                                    print(key)
                                    print(type(headers[key]))
                                    flow.request.headers[key] = headers[key]
                                    print(f'Inserted headers {key}')  # DEBUG
                                except Exception as e:
                                    print(f'Error in request to place header {key} into flow object')

                    self.updateToDBbyID('is_modified', 1, self.last_row_id)

                    # Handle content
                    if unpacked_content is not None and isinstance(unpacked_content, str):
                        try:
                            byte_content = unpacked_content.encode('utf-8')
                        except Exception as e:
                            print(f"Error encoding content {e}")

                        if byte_content:
                            flow.request.content = byte_content
                        print('Inserted content')  # DEBUG

                print(flow.request.headers) #DEBUG
                if unpacked_content: #DEBUG
                    print(flow.request.content) #DEBUG

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
                # Handle Modified, Parse, Resume, Reset Modified
                unpacked_content = None
                modified_content = get_modified()
                modified_content = modified_content.replace("'", '"')
                modified_content = modified_content.replace('null', 'None')
                if modified_content:
                    print(modified_content)
                    print(type(modified_content))
                    traffic_dict = None
                    data, content = self.extractContent(modified_content)

                    try:
                        # Parse the JSON string into a Python dictionary
                        traffic_dict = ast.literal_eval(data)
                    except (ValueError, SyntaxError) as e:
                        traffic_dict = None
                        print(f"Error with ast decoding {e}")
                    except Exception as e:
                        # Catch any other exceptions
                        print(f"Unexpected error: {e}")
                        traffic_dict = None

                    if content:
                        try:
                            # Parse the JSON string into a Python dictionary
                            unpacked_content = ast.literal_eval(content)
                        except (ValueError, SyntaxError) as e:
                            unpacked_content = None
                            print(f"Error with ast decoding {e}")
                        except Exception as e:
                            # Catch any other exceptions
                            print(f"Unexpected error: {e}")
                            unpacked_content = None

                    if traffic_dict:
                        # Handle HTTP
                        http_version = traffic_dict.get('http_version')
                        if http_version:
                            flow.response.http_version = http_version
                            print('Inserted HTTP Version')  # DEBUG
                        # Handle status code
                        status_code = traffic_dict.get('status_code')
                        if status_code:
                            flow.response.status_code = status_code
                            print('Inserted status code')  # DEBUG
                        # Handle reason
                        reason = traffic_dict.get('reason')
                        if reason:
                            flow.response.reason = reason
                            print('Inserted reason')  # DEBUG
                        # Handle headers
                        headers = traffic_dict.get('headers')
                        print(type(headers))
                        if headers:
                            for key in headers:
                                try:
                                    print(key)
                                    print(type(headers[key]))
                                    flow.response.headers[key] = headers[key]
                                    print(f'Inserted headers {key}')  # DEBUG
                                except Exception as e:
                                    print(f'Error in request to place header {key} into flow object')

                    self.updateToDBbyID('is_modified', 1, self.last_row_id)

                    # Handling any content
                    if unpacked_content is not None and isinstance(unpacked_content, str):
                        # Handle content
                        try:
                            byte_content = unpacked_content.encode('utf-8')
                        except Exception as e:
                            print(f"Error encoding content {e}")

                        if byte_content:
                            flow.response.content = byte_content
                        print('Inserted content')  # DEBUG

                    print(flow.request.headers)  # DEBUG
                    if unpacked_content:  # DEBUG
                        print(flow.request.content)  # DEBUG

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

    def extractContent(self, input_string):
        match = re.search(pattern, input_string, re.DOTALL)
        if match:
            # Extract the content
            content = match.group(1)
            print(f"Extracted content: {content}")
            # Remove the content from the original string
            modified_string = re.sub(pattern, '', input_string, flags=re.DOTALL)
            return modified_string, content
        else:
            content = None
            return input_string, content


    def callToFlask(self, type):
        global flask_url
        url = f"{flask_url}/incoming-flow"  # Call to flask
        payload = {
            "type": type  # request or response
        }
        response = requests.post(url, json=payload)
        # Print the response from Flask
        if response.status_code == 200:
            print(f"Success call for CallToFlask")
        else:
            print(f"Error when using CallToFlask")


addons = [TrafficController()]
