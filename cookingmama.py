from mitmproxy import http
import os
import json, requests, ast
import sqlite3  # Import SQLite
import config, subprocess, time
import broxy


# App Part
processes = (["mitmdump", "-p", config.mitm_port, "-s", "howfastcanicook.py"],
             ["python", "broxy.py"])

subprocess.Popen(processes[0])
time.sleep(2)
broxy.launch_broxy()