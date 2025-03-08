from mitmproxy import http
import os
import json, requests, ast
import sqlite3  # Import SQLite
from bs4 import BeautifulSoup
from urllib.parse import parse_qs
import config, subprocess, time, re

import mimetypes


class TrafficController:
    def __init__(self):
        self.flow = None  # FLOW
        self.conn = None  # DB
        self.cursor = None  # DB
        self.last_row_id = None  # Latest
        self.count = 0
        self.limit = 8

    def request(self, flow: http.HTTPFlow) -> None:
        content_type = flow.request.headers.get("Content-Type", "Unknown").lower()
        print(content_type) if content_type else print("content-type none")
        # Ignore Chrome auto calls to optimizationguide and safebrowsing
        if "optimizationguide-pa.googleapis.com" in flow.request.url:
            flow.resume()
            print("request to optimizationguide-pa.googleapis.com skipped")
        elif 'safebrowsingohttpgateway.googleapis.com' in flow.request.url:
            flow.resume()
            print("request to safebrowsingohttpgateway.googleapis.com skipped")
        elif self.count <= self.limit:
            try:
                pure_content = flow.request.content
                print(f"Pure_content of type : {type(pure_content)} \n{pure_content}\n\n")
                print(f"Decoded Version : {self.decode_content(content_type, pure_content)}")
                self.count += 1
            except Exception as e:
                get_content = flow.request.get_content()
                print(f"Content() of type : {type(get_content)} \n{get_content}\n\n")
                print(f"Decoded Version : {self.decode_content(content_type, get_content)}")

    def response(self, flow: http.HTTPFlow) -> None:
        content_type = flow.response.headers.get("Content-Type", "Unknown").lower()
        print(content_type) if content_type else print("content-type none")
        # response_data_string = json.dumps(response_data, indent=4)
        if "optimizationguide-pa.googleapis.com" in flow.request.url:
            flow.resume()
            print("response from optimizationguide-pa.googleapis.com skipped")
        elif 'safebrowsingohttpgateway.googleapis.com' in flow.request.url:
            flow.resume()
            print("response from safebrowsingohttpgateway.googleapis.com skipped")
        elif self.count <= self.limit:
            try:
                pure_content = flow.response.content
                print(f"Pure_content of type : {type(pure_content)} \n{pure_content}\n\n")
                print(f"Decoded Version : {self.decode_content(content_type, pure_content)}")
                self.count += 1
            except Exception as e:
                get_content = flow.response.get_content()
                print(f"Content() of type : {type(get_content)} \n{get_content}\n\n")
                print(f"Decoded Version : {self.decode_content(content_type, get_content)}")

    def decode_content(self, content_type, byte_data):
        match = re.search(r'charset=([^\s;]+)', content_type)
        encoding = match.group(1) if match else 'utf-8'

        # Handle application/json content
        if 'application/json' in content_type:
            print("Handling JSON data")
            if b")]}\'" in byte_data:
                json_string = byte_data.decode('utf-8')[4:]
            else:
                try:
                    json_data = json.loads(byte_data.decode(encoding, errors='ignore'))
                    print("JSON Content:", json_data)
                except:
                    print('error json decoding')
            return json_data
        # Handle HTML content
        elif 'text/html' in content_type:
            html_data = byte_data.decode(encoding, errors='ignore')
            soup = BeautifulSoup(html_data, 'html.parser')
            print("HTML Title:", soup if soup else "No Soup cuh")
        # Handle text-based content
        elif 'text/' in content_type:
            text_data = byte_data.decode(encoding, errors='ignore')
            print("Text Content:", text_data[:200])
        elif 'application/x-www-form-urlencoded' in content_type:
            print("Handling URL-encoded data")
            return parse_qs(byte_data)  # Parse URL-encoded data
        else:
            print("Not equipped to decode this datatype")
            return byte_data


addons = [TrafficController()]
