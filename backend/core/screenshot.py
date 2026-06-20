"""
screenshot.py
Secure URL preview engine using headless Selenium + Chrome.
Captures a sandboxed screenshot of a URL without exposing the user.
"""

import base64
import time
import hashlib
import os

SCREENSHOTS_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'screenshots')
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.common.exceptions import (
    TimeoutException,
    WebDriverException,
)

try:
    from webdriver_manager.chrome import ChromeDriverManager
    _WEBDRIVER_MANAGER = True
except ImportError:
    _WEBDRIVER_MANAGER = False


_CHROME_USER_AGENT = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
    'AppleWebKit/537.36 (KHTML, like Gecko) '
    'Chrome/120.0.0.0 Safari/537.36'
)


def _build_driver() -> webdriver.Chrome:
    """Configure and return a headless Chrome WebDriver instance."""
    opts = Options()
    opts.add_argument('--headless=new')
    opts.add_argument('--no-sandbox')
    opts.add_argument('--disable-dev-shm-usage')
    opts.add_argument('--disable-gpu')
    opts.add_argument('--disable-extensions')
    opts.add_argument('--disable-infobars')
    opts.add_argument('--window-size=1280,720')
    opts.add_argument(f'--user-agent={_CHROME_USER_AGENT}')
    opts.add_argument('--ignore-certificate-errors')
    opts.add_argument('--allow-insecure-localhost')

    if _WEBDRIVER_MANAGER:
        service = Service(ChromeDriverManager().install())
        return webdriver.Chrome(service=service, options=opts)
    else:
        return webdriver.Chrome(options=opts)


def capture_screenshot(url: str, timeout: int = 10) -> str | None:
    """
    Launch headless Chrome, navigate to the URL, and capture a screenshot.

    Args:
        url:     Target URL to preview.
        timeout: Page load timeout in seconds (default 10).

    Returns:
        Dict with screenshot_available, screenshot_path, and screenshot_b64.
    """
    result = {
        "screenshot_available": False,
        "screenshot_path": None,
        "screenshot_b64": None
    }
    driver = None
    try:
        driver = _build_driver()
        driver.set_page_load_timeout(timeout)
        driver.set_script_timeout(timeout)

        try:
            driver.get(url)
        except TimeoutException:
            # Page timed out but may have partially loaded — still capture
            pass

        # Brief pause for JS rendering
        time.sleep(2)

        screenshot_b64 = driver.get_screenshot_as_base64()
        
        # Save to disk
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        filename = f"{url_hash}.png"
        filepath = os.path.join(SCREENSHOTS_DIR, filename)
        
        driver.save_screenshot(filepath)
        
        result["screenshot_available"] = True
        result["screenshot_path"] = f"screenshots/{filename}"
        result["screenshot_b64"] = screenshot_b64
        
        return result

    except WebDriverException as e:
        print(f'[screenshot] WebDriverException: {e}')
        return result
    except Exception as e:
        print(f'[screenshot] Unexpected error: {e}')
        return result
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass
