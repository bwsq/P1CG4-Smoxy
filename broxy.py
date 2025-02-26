from playwright.sync_api import sync_playwright

# Proxy settings
PROXY_SERVER = "http://0.0.0.0:9090"  # Replace with your proxy address

# Default Startup Website
TARGET_URL = "https://example.com/"

DOWNLOAD_PATH = "/Users/jonathantok/Downloads/"


def launch_broxy():
    with sync_playwright() as p:
        try:
            browser = p.chromium.launch(
                headless=False,
                channel="chrome",  # Use the installed Chrome browser
                args=[
                    "--no-first-run",  # prevent Chrome first-run experience
                    "--no-default-browser-check",  # hide automation-related flags
                    "--disable-blink-features=AutomationControlled",  # removes the automation flag
                    f"--proxy-server={PROXY_SERVER}",
                ],
                ignore_default_args=["--enable-automation"],
                proxy={
                    "server": PROXY_SERVER
                }
            )
            context = browser.new_context(
                accept_downloads=True,
                ignore_https_errors=True,
                viewport={"width": 1440, "height": 900},  # common viewport size to be less likely flagged H1920 W1080
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            )
            page = context.new_page()
            page.goto(TARGET_URL)

            # End usage
            print("Press Enter to close browser...")
            input()
            browser.close()



        except Exception as e:
            print(f"Error navigating to {TARGET_URL}: {e}")


if __name__ == "__main__":
    launch_broxy()
