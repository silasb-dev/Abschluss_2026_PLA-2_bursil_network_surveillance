#--------------------------------
# Author: Silas Burkhard
# Created: 26-06-10
# Last Changed: 26-06-10
# Description:
# Simulate C2 Traffic
# that uses jitter to hide
#--------------------------------
import requests
import time
import random


while True:
    # Make get request to site
    requests.get("http://httpforever.com/")
    # Wait some time to mimic beaconing and randomness for jitter
    time.sleep(30+random.uniform(-5,5))

