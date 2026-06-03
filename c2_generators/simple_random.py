import requests
import time
import random


while True:
    requests.get("https://example.com")
    time.sleep(30+random.uniform(-5,+5))

