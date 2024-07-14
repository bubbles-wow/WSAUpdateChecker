import os
import time
import gzip
import json
import base64
import datetime
import subprocess

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from datetime import datetime, timedelta, timezone


path = os.path.dirname(__file__)
last_used_time = datetime.now(timezone(timedelta(hours=8)))
expires_time = datetime.fromtimestamp(last_used_time.timestamp() + 86400).astimezone(timezone(timedelta(hours=8)))
login_url = "https://login.live.com/ppsecure/InlineConnect.srf?id=80604&platform=android2.1.0510.1018&client_id=android-app://com.mojang.minecraftearth.H62DKCBHJP6WXXIV7RBFOGOL4NAK4E6Y"

service = Service(os.path.join(os.getenv("CHROMEWEBDRIVER"), "chromedriver"))
option = webdriver.ChromeOptions()
option.add_argument("--headless")
driver = webdriver.Chrome(service=service, options=option)
driver.get(login_url)
time.sleep(10)
driver.find_element("id", "i0116").send_keys(os.getenv("ACCOUNT"))
time.sleep(5)
driver.find_element("id", "idSIButton9").click()
while driver.find_element("id", "i0118") == None:
    time.sleep(1)
driver.find_element("id", "i0118").send_keys(os.getenv("PASSWORD"))
time.sleep(5)
try:
    driver.find_element("id", "idSIButton9").click()
except Exception as e:
    pass
count = 0
while login_url == driver.current_url:
    count += 1
    time.sleep(1)
    if count % 30 == 0:
        driver.find_element("id", "idSIButton9").click()
cookies = driver.get_cookies()
driver.quit()
property = None
for item in cookies:
    if item["name"] == "Property":
        property = item["value"]
        break
property = json.loads(property)
compress = gzip.compress(json.dumps(property).encode())
value = base64.b64encode(compress).decode("utf-8")
process = subprocess.Popen([os.path.join(path, "bin", "GetMSAToken"), value], stdout=subprocess.PIPE)
process.wait()
token = process.stdout.read().decode("utf-8").replace("\r\n", "")

time_now = last_used_time.strftime('%Y-%m-%d %H:%M:%S')
with open(os.path.join(path, "token.conf"), "w") as f:
    f.write(f"update_time={time_now} (UTC+8)\n")
    f.write(f"user_code={token}")
    f.close()