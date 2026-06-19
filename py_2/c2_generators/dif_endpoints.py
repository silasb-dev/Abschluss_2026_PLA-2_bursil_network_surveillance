#--------------------------------
# Author: Silas Burkhard
# Created: 26-06-10
# Last Changed: 26-06-10
# Description:
# Simulate C2 Traffic 
# which dynamiclly changes 
# endpoints
#--------------------------------
import requests
import time
import random

# Endpoints to choose from
endpoints = []

while True:
    # Make get request to random endpoint
    requests.get(random.choice(endpoints))
    # Set interval to mimic beaconing
    time.sleep(30)