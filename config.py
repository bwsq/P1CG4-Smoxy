# APP
TABLE = "traffic"  # Database filename
DATABASE_FILE = f"{TABLE}.db"  # Database filename w .db extension
mitm_port = "9090"  # MITM proxy
flask_port = '5050'  # Flask control panel port
flask_url = f'http://localhost:{flask_port}/'

def toggle_interception():
    interception_enabled = stringToBoolean(get_interception_enabled())  # before change
    print(f"1 : interception {interception_enabled}")
    interception_enabled = not interception_enabled  # toggle
    print(f"2 : interception not =  {interception_enabled}")
    set_interception_enabled(interception_enabled)  # toggle
    interception_enabled = stringToBoolean(get_interception_enabled())  # new value
    print(f"3 : after setting interception {interception_enabled}")
    state = "Enabled" if interception_enabled else "Disabled"  # For frontend interrupt button
    set_resume_signal(True)  # Trigger resume to ensure flow continues
    return state

# BROXY
PROXY_SERVER = "http://0.0.0.0:9090"  # MITM proxy
TARGET_URL = "https://example.com/"  # Default Website playwright launches in chromium
DOWNLOAD_PATH = "/Users/jonathantok/Downloads/"  # Your device download path (optional)


# PROXY
def set_interception_enabled(value):
    try:
        with open('intercept.txt', 'w') as file:
            value = str(value)
            file.write(value)
    except Exception as e:
        print(f"An error occurred for set_interception_enabled: {e}")


def get_interception_enabled():
    try:
        with open('intercept.txt', 'r') as file:
            interception_enabled = file.read()
    except Exception as e:
        print(f"An error occurred for get_interception_enabled: {e}")
    return interception_enabled


def set_resume_signal(value):
    try:
        with open('resume.txt', 'w') as file:
            value = str(value)
            file.write(value)
    except Exception as e:
        print(f"An error occurred for set_resume_signal: {e}")


def get_resume_signal():
    try:
        with open('resume.txt', 'r') as file:
            resume_signal = file.read()
    except Exception as e:
        print(f"An error occurred for get_resume_signal: {e}")
    return resume_signal


def get_drop_signal():
    try:
        with open('drop.txt', 'r') as file:
            drop_signal = file.read()
    except Exception as e:
        print(f"An error occurred for drop_signal: {e}")
    return drop_signal


def set_drop_signal(value):
    try:
        with open('drop.txt', 'w') as file:
            value = str(value)
            file.write(value)
    except Exception as e:
        print(f"An error occurred for drop_signal: {e}")


def stringToBoolean(string):
    if string == 'True':
        return True
    else:
        return False
