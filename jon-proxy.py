import time
import re
from mitmproxy import http
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

    def saveToDB(self, flowtype, data, intercept):

        try:
            self.conn = sqlite3.connect(DATABASE_FILE)
            self.cursor = self.conn.cursor()

            # Request Body (if present)
            body = None

            if flowtype == 'request':
                if self.flow.request.content:
                    body = self.flow.request.content
                    # body = self.flow.request.content.decode("utf-8", errors="ignore") # Will work for UTF-8 texts
                self.cursor.execute(
                    "INSERT INTO traffic (flow_type, url, path, port, method, scheme, http_version, headers, content, intercepted) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (flowtype,
                     self.flow.request.pretty_url,
                     data['path'],
                     data['port'],
                     data['method'],
                     data['scheme'],
                     data['http_version'],
                     data['headers'],
                     body,
                     intercept
                     )
                )
            elif flowtype == 'response':
                if self.flow.response.content:
                    body = self.flow.response.content.decode("utf-8", errors="ignore")
                    print(f"proxy saveToDB Response Body = {body}")
                if not body:
                    body = data['content']
                self.cursor.execute(
                    "INSERT INTO traffic (flow_type, url, path, status_code, reason, http_version, headers, content, intercepted) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (flowtype,
                     data['url'],
                     data['path'],
                     data['status_code'],
                     data['reason'],
                     data['http_version'],
                     data['headers'],
                     body,
                     intercept
                     )
                )

            self.last_row_id = self.cursor.lastrowid

            self.conn.commit()
            self.conn.close()
            return 1  # success

        except sqlite3.Error as e:
            print("sqllite error in  request")  # debug
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
            "content": flow.request.content,
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

                print("DEDBUGGING - ", type(modified_content))

                modified_content = modified_content.replace("'", '"')
                modified_content = modified_content.replace('null', 'None')

                if len(modified_content) != 0:
                    print(modified_content)
                    print(type(modified_content))

                    modified_content = modified_content.replace("\\n", "")
                    modified_content = modified_content.replace("\\", "")
                    modified_content = modified_content.replace("\"\"", "\"")


                    traffic_dict = None
                    print(f'\nMODIFIED BODY [{type(modified_content)}]\n{modified_content}')
                    try:
                        # traffic_dict = ast.literal_eval(modified_content)
                        traffic_dict = json.loads(modified_content)
                        print(f"traffic_dict of type {type(traffic_dict)} : {traffic_dict[:100]}")

                    except Exception as e:
                        print(f'Proxy.py Response : Error decoding modified traffic')

                    # data, content = self.extractContent(modified_content)
                    # print(' proxy reconstructing request' )
                    # print(f'\n\nDATA [{type(data)}]\n{data}')
                    # print(f'\n\nCONTENT [{type(content)}]\n{content}')
                    # try:
                    #     # Parse the JSON string into a Python dictionary
                    #     traffic_dict = ast.literal_eval(data)
                    #     print(f'\n\nTRAFFIC_DICT [{type(traffic_dict)}]\n{traffic_dict}')
                    #
                    #     # traffic_dict = json.loads(data)
                    # except Exception as e:
                    #     # Catch any other exceptions
                    #     print(f"Error with ast decoding entire dict {e}")
                    #     traffic_dict = None
                    #
                    # if content:
                    #     try:
                    #         unpacked_content = ast.literal_eval(content)
                    #         print(f'\n\nUNPACKED_CONTENT [{type(unpacked_content)}]\n{unpacked_content}')
                    #
                    #         #unpacked_content = json.loads(content)
                    #     except (ValueError, SyntaxError) as e:
                    #         unpacked_content = None
                    #         print(f"Request : Error with ast decoding content {e}")
                    #     except Exception as e:
                    #         # Catch any other exceptions
                    #         print(f"Request :Error with ast decoding content {e}")
                    #         unpacked_content = None
                    #
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

                    # Handling any content
                    if 'content' in traffic_dict or 'Content' in traffic_dict:
                        # Handle content
                        try:
                            if isinstance(traffic_dict, str):
                                try:
                                    byte_content = traffic_dict['content'].encode('utf-8')
                                except Exception as e:
                                    print('Error in proxy.py response handling : converting content to bytes')
                                    byte_content = None
                            if byte_content:
                                flow.request.content = byte_content

                        except Exception as e:
                            print(f"Error encoding content {e}")


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

                    modified_content = modified_content.replace("\\n", "")
                    modified_content = modified_content.replace("\\", "")
                    modified_content = modified_content.replace("\"\"", "\"")

                    traffic_dict = None
                    print(f'\nMODIFIED BODY [{type(modified_content)}]\n{modified_content}')
                    try:
                        traffic_dict = json.loads(modified_content)
                        # traffic_dict = ast.literal_eval(modified_content)
                        print(f"traffic_dict of type {type(traffic_dict)} : {traffic_dict[:100]}")

                    except Exception as e:
                        print(f'Proxy.py Response : Error decoding modified traffic : \nerror : {e}')


                    # data, content = self.extractContent(modified_content)
                    # print(' proxy reconstructing response' )
                    # print(f'\nDATA [{type(data)}]\n{data}')
                    # print(f'\n\nCONTENT [{type(content)}]\n{content}')

                    # try:
                    #     # Parse the JSON string into a Python dictionary
                    #     # traffic_dict = ast.literal_eval(data)
                    #     print(f'\n\nTRAFFIC_DICT [{type(traffic_dict)}]\n{traffic_dict}')
                    #     traffic_dict = json.loads(data)
                    # except Exception as e:
                    #     # Catch any other exceptions
                    #     print(f"Response : Error with ast decoding entire traffic {e}")
                    #     traffic_dict = None

                    # if content:
                    #     try:
                    #         # Parse the JSON string into a Python dictionary
                    #         unpacked_content = ast.literal_eval(content)
                    #         print(f'\n\nUNPACKED_CONTENT [{type(unpacked_content)}]\n{unpacked_content}')
                    #         # unpacked_content = json.loads(content)
                    #     except Exception as e:
                    #         # Catch any other exceptions
                    #         print(f"Error with ast decoding content {e}")
                    #         print(content)
                    #         unpacked_content = None

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
                    if 'content' in traffic_dict or 'Content' in traffic_dict:
                        # Handle content
                        try:
                            if isinstance(traffic_dict, str):
                                try:
                                    byte_content = traffic_dict['content'].encode('utf-8')
                                except Exception as e:
                                    print('Error in proxy.py response handling : converting content to bytes')
                                    byte_content = None
                            if byte_content:
                                flow.response.content = byte_content

                        except Exception as e:
                            print(f"Error encoding content {e}")

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
