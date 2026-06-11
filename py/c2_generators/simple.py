import requests
import time


while True:
    requests.get("http://httpforever.com/")
    time.sleep(15)
