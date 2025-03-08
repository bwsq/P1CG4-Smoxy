# from playwright.sync_api import sync_playwright

# # Proxy settings
# PROXY_SERVER = "http://0.0.0.0:9090"  # Replace with your proxy address

# # Default Startup Website
# TARGET_URL = "https://example.com/"

# DOWNLOAD_PATH = "/Users/jonathantok/Downloads/"


# def launch_broxy():
#     with sync_playwright() as p:
#         try:
#             browser = p.chromium.launch(
#                 headless=False,
#                 channel="chrome",  # Use the installed Chrome browser
#                 args=[
#                     "--no-first-run",  # prevent Chrome first-run experience
#                     "--no-default-browser-check",  # hide automation-related flags
#                     "--disable-blink-features=AutomationControlled",  # removes the automation flag
#                     f"--proxy-server={PROXY_SERVER}",
#                 ],
#                 ignore_default_args=["--enable-automation"],
#                 proxy={
#                     "server": PROXY_SERVER
#                 }
#             )
#             context = browser.new_context(
#                 accept_downloads=True,
#                 ignore_https_errors=True,
#                 viewport={"width": 1440, "height": 900},  # common viewport size to be less likely flagged H1920 W1080
#                 user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
#             )
#             page = context.new_page()
#             page.goto(TARGET_URL)

#             # End usage
#             print("Press Enter to close browser...")
#             input()
#             browser.close()



#         except Exception as e:
#             print(f"Error navigating to {TARGET_URL}: {e}")


# if __name__ == "__main__":
#     launch_broxy()

# from playwright.sync_api import sync_playwright

# # Proxy settings
# PROXY_SERVER = "http://0.0.0.0:9090"  # Replace with your proxy address

# # Default Startup Website
# TARGET_URL = "https://example.com/"

# DOWNLOAD_PATH = "/Users/jonathantok/Downloads/"


# def launch_broxy():
#     with sync_playwright() as p:
#         try:
#             browser = p.chromium.launch_persistent_context(
#                 user_data_dir=r"C:\Users\sherm\AppData\Local\Google\Chrome\User Data\Profile 1",
#                 headless=False,
#                 channel="chrome",  # Use the installed Chrome browser
#                 args=[
#                     "--no-first-run",  # prevent Chrome first-run experience
#                     "--no-default-browser-check",  # hide automation-related flags
#                     "--disable-blink-features=AutomationControlled",  # removes the automation flag
#                     f"--proxy-server={PROXY_SERVER}",
#                 ],
#                 ignore_default_args=["--enable-automation"],
#                 proxy={
#                     "server": PROXY_SERVER
#                 }
#             )
#             context = browser.new_context(
#                 accept_downloads=True,
#                 ignore_https_errors=True,
#                 viewport={"width": 1440, "height": 900},  # common viewport size to be less likely flagged H1920 W1080
#                 user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
#             )
#             page = context.new_page()
#             page.goto(TARGET_URL)

#             # End usage
#             print("Press Enter to close browser...")
#             input()
#             browser.close()



#         except Exception as e:
#             print(f"Error navigating to {TARGET_URL}: {e}")


# if __name__ == "__main__":
#     launch_broxy()

from playwright.sync_api import sync_playwright

# Proxy settings
PROXY_SERVER = "http://127.0.0.1:9090"  # Use 127.0.0.1 (not 0.0.0.0) for local proxy
# Default Startup Website
TARGET_URL = "https://example.com/"

def launch_broxy():
    with sync_playwright() as p:
        try:
            context = p.chromium.launch_persistent_context(
                user_data_dir=r"C:\Users\sherm\AppData\Local\Google\Chrome\User Data\Profile 1",
                headless=False,
                channel="chrome",  # Use system Chrome
                args=[
                    "--no-first-run",  # Skip first-run setup
                    "--no-default-browser-check",  # Avoid default browser popup
                    "--disable-blink-features=AutomationControlled",  # Attempt to reduce automation detection
                    "--ignore-certificate-errors"  # Optional: ignore SSL issues if mitmproxy CA is missing
                ],
                proxy={
                    "server": PROXY_SERVER
                },
                ignore_default_args=["--enable-automation"]  # Hide the "Chrome is being controlled" bar
            )

            page = context.new_page()  # Directly create page from context (not new_context)

            page.goto(TARGET_URL)

            print("Press Enter to close browser...")
            input()
            context.close()

        except Exception as e:
            print(f"Error navigating to {TARGET_URL}: {e}")

if __name__ == "__main__":
    launch_broxy()