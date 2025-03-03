import sqlite3, ast, json, base64, urllib.parse
from bs4 import BeautifulSoup
from config import (DATABASE_FILE, mitm_port, flask_port, toggle_interception,
                    get_interception_enabled, stringToBoolean, set_resume_signal,
                    set_drop_signal)


def query_database(query):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute(query)
    data = cursor.fetchall()
    conn.close()
    return data




def decode_content(content_type, data):
    content_type = content_type.lower()
    data = data[0][0]

    if 'application/json' in content_type:
        print("Handling JSON data")
        # decode into string and remove the non-JSON part (prefix)
        # json_string = data.decode('utf-8')[4:]
        if b")]}\'" in data:
            json_string = data.decode('utf-8')[4:]
        else:
            json_string = data.decode('utf-8')
        json_data = json.loads(json_string)
        print(type(json_data))  # dict
        for key in json_data:
            if json_data[f'{key}']:
                item = json_data[f'{key}']
                if type(item) is list:
                    for i in item:
                        print(f'{i}\n')

        json_load = json.loads(json_string)
        # base64_string = data['bgasy'][1] # Extract the base64 string (second element in the list)
        # decoded_data = base64.b64decode(base64_string)         # Decode the base64 string
        # print(decoded_data)
        return 1
    elif "text/javascript" in content_type or "application/javascript" in content_type:
        print("Handling Javascript data")
        return data.decode('utf-8')
    elif "text/css" in content_type:
        print("Handling CSS data")
        css_content = data.decode('utf-8')
        return css_content
    elif 'text/html' in content_type:
        print("Handling HTML data")
        return BeautifulSoup(data, 'html.parser')
    elif 'application/x-www-form-urlencoded' in content_type:
        print("Handling URL-encoded data")
        # Parse URL-encoded data
        from urllib.parse import parse_qs
        return parse_qs(data)
    elif 'text/plain' in content_type:
        print("Handling plain text data")
        # Handle plain text data
        return data.decode('utf-8')
    else:
        print("Not equipped to decode this datatype")
        return data


id = 60 # css # 89
response = query_database(f"SELECT headers FROM traffic WHERE id = {id}")

# handle headers (need to be parsed in frontend)
response = query_database(f"SELECT headers FROM traffic WHERE id = {id}")  # dictionary of headers
headers = ast.literal_eval(response[0][0]) if response else None

# Handles content type (if any)
content_type = None
for key in headers.keys():
    if key.lower() == 'content-type':
        content_type = headers['content-type']  # must account for Content-Type and content-type in headers
        print(content_type)
        break

# Handles content  (if any)
if content_type:
    data = query_database(f"SELECT content FROM traffic WHERE id = {id}")  # get content
    if data:
        content = decode_content(content_type, data)
