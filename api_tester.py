import time
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.options import Options as ChromeOptions
import requests

def get_headless_driver():
    """Initializes and returns a headless Chrome WebDriver."""
    options = ChromeOptions()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36")
    driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=options)
    return driver

def main():
    target_url = "https://tayseerme.com"
    api_url = "https://tayseerme.com/api/bookmarks/data"

    print(f"[+] Initializing headless browser and visiting {target_url}")
    driver = get_headless_driver()
    driver.get(target_url)
    time.sleep(5)  # Wait for the page and JS to load

    print("[+] Extracting cookies...")
    cookies = driver.get_cookies()
    driver.quit()

    if not cookies:
        print("[-] No cookies found. Exiting.")
        return

    print(f"[+] Found cookies: {cookies}")

    # Prepare session and headers
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36"})

    # Add cookies to the session
    for cookie in cookies:
        session.cookies.set(cookie['name'], cookie['value'], domain=cookie['domain'])
    
    # Try to find the XSRF token from the cookies
    xsrf_token = next((cookie['value'] for cookie in cookies if 'XSRF' in cookie['name'].upper()), None)
    if xsrf_token:
        print(f"[+] Found XSRF token: {xsrf_token}")
        session.headers.update({'X-XSRF-TOKEN': xsrf_token})
    else:
        print("[-] XSRF token not found in cookies.")

    print(f"[+] Sending request to API endpoint: {api_url}")
    try:
        response = session.get(api_url)
        print(f"[+] API Response Status Code: {response.status_code}")
        print("[+] API Response Headers:")
        for key, value in response.headers.items():
            print(f"  {key}: {value}")
        
        print("[+] API Response Body:")
        # Try to print as JSON, fallback to text
        try:
            print(response.json())
        except requests.exceptions.JSONDecodeError:
            print(response.text)

    except Exception as e:
        print(f"[-] An error occurred: {e}")

if __name__ == "__main__":
    main()
