import os
import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

def take_reference_screenshots():
    # Setup Chrome options
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--window-size=1280,1024")
    
    driver = webdriver.Chrome(options=chrome_options)
    
    os.makedirs('backend/assets/reference_logins', exist_ok=True)
    
    targets = {
        'github': 'https://github.com/login',
        'microsoft': 'https://login.microsoftonline.com/',
        'google': 'https://accounts.google.com/',
        'paypal': 'https://www.paypal.com/signin',
        'amazon': 'https://www.amazon.com/ap/signin?openid.pape.max_auth_age=0&openid.return_to=https%3A%2F%2Fwww.amazon.com%2F%3Fref_%3Dnav_ya_signin&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.assoc_handle=usflex&openid.mode=checkid_setup&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0'
    }
    
    for brand, url in targets.items():
        print(f"Fetching {brand}...")
        try:
            driver.get(url)
            time.sleep(3) # Wait for page to load
            driver.save_screenshot(f'backend/assets/reference_logins/{brand}.png')
            print(f"Saved {brand}.png")
        except Exception as e:
            print(f"Failed {brand}: {e}")
            
    driver.quit()

if __name__ == "__main__":
    take_reference_screenshots()
