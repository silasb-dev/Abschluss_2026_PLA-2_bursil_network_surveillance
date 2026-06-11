import requests
import time
import random

endpoints = []

while True:
    requests.get(random.choice(endpoints))
    time.sleep(30)