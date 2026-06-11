import requests
import time
import random


while True:
    requests.get("http://httpforever.com/")
    time.sleep(30+random.uniform(-5,5))

