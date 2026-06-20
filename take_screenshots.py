import time
import os
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.by import By

def take_screenshots():
    options = Options()
    options.add_argument('--headless')
    options.add_argument('--window-size=1280,1024')
    options.add_argument('--disable-gpu')
    options.add_argument('--no-sandbox')
    
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
    
    output_dir = r"C:\Users\SPOORTHI\.gemini\antigravity\brain\e399cbbe-fb7c-4537-8d56-75a9c29e146c"
    
    try:
        # 1. Scanner UI
        driver.get('http://localhost:5173/')
        time.sleep(3)
        try:
            # Type something and click scan
            textarea = driver.find_element(By.TAG_NAME, "textarea")
            textarea.send_keys("https://paypal-secure-update.xyz/login")
            btn = driver.find_element(By.XPATH, "//button[contains(text(), 'Scan')]")
            btn.click()
            time.sleep(3) 
        except Exception as e:
            print("Scan err:", e)
        driver.save_screenshot(os.path.join(output_dir, 'ui_scanner.png'))
        print("Saved ui_scanner.png")
        
        # 2. Intelligence Hub (Trust Graph)
        try:
            # Click Intelligence Hub sidebar
            btn = driver.find_element(By.XPATH, "//button[.//span[text()='Intelligence Hub']]")
            btn.click()
            time.sleep(2)
        except Exception as e:
            print("Sidebar err:", e)
            
        driver.save_screenshot(os.path.join(output_dir, 'ui_trust_graph.png'))
        print("Saved ui_trust_graph.png")
        
        # 3. Forecast Validation
        try:
            # Scroll down to see forecast validation
            driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
            time.sleep(1)
        except Exception as e:
            print("Forecast err:", e)
            
        driver.save_screenshot(os.path.join(output_dir, 'ui_forecast.png'))
        print("Saved ui_forecast.png")
        
    finally:
        driver.quit()

if __name__ == '__main__':
    take_screenshots()
