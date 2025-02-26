# P1CG4--Smoxy-

Current code in Jonathan Branch

Step 1 : Create a folder and virtual environment venv <br/>
Step 2 : Place all the files and folder in <br/>
Step 3 : pip install all missing dependencies <br/>
<br/>
INFO<br/>
App.py controls launches other components and handles flask/control panel<br/>
Broxy.py handles browser<br/>
Proxy.py used by mitmproxy to alter request and response behaviour<br/>
config.py contains global variables and help access (resume.txt , intercept.txt ) which acts as a form of variable as we can't pass any variables into mitmproxy once it's running)<br/>

<br/>
App.py is the entry file, run that.<br/>
mitmproxy and flask both uses ports, they can be changed in the app.py under mitm_port and flask_port.<br/>
Feel free to ask moi for any issue
