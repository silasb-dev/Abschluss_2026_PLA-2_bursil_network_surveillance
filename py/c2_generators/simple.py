#--------------------------------
# Author: Silas Burkhard
# Created: 26-06-10
# Last Changed: 26-06-10
# Description:
# Simulate C2 Traffic
# that periodicly sends
# get requests
#--------------------------------
import requests
import time


while True:
    # send get request
    requests.get("http://httpforever.com/")
    # Wait some time to mimic beaconing
    time.sleep(15)
