#--------------------------------
# Author: Silas Burkhard
# Created: 26-06-10
# Last Changed: 26-06-11
# Description:
# Main File to join
# other files togheter.
# extract features ->
# calculate iso Forest ->
# plot results
#--------------------------------
from algorithm import i_forest_t_test
from parser import extract
from visualize import show
import pandas as pd
import time

# PARAMETERS ######################################
CAPTURE_FILE = "../captures/400k.pcapng"
USER_AGENT = "python-requests/2.34.2" # python-requests/2.34.2 python-requests/2.32.5
FEATURE_LIST = ["time_since_prev_flow","dst2src_max_ps","dst2src_stddev_ps","protocol_id","src2dst_stddev_ps","src2dst_max_ps"]
NEW_FEATURE_LIST = ["time_since_prev_flow_mean",
                    "dst2src_max_ps_mean",
                    "dst2src_stddev_ps_mean",
                    "protocol_id_mean",
                    "src2dst_stddev_ps_mean",
                    "src2dst_max_ps_mean"]
###################################################

print("Extracting...")
st = time.time()
# Extract Features and the id's of the malicious traffic
data, m_id = extract.l_file(CAPTURE_FILE,m_traffic_u_agent=USER_AGENT)
tt = round(time.time() - st,2)
print(f"Duration: {tt}s")
data.to_csv("data.csv")
print("Isolating...")
st = time.time()
# Use t-sne and then k-means clustering for better analysis
data,mc_id = i_forest_t_test.combination(data,FEATURE_LIST,new=True,m_id=m_id)
print(mc_id)
FEATURE_LIST.append("cluster")
# Use Isolation forest on the optimized data
data = i_forest_t_test.isolation_forest(data,NEW_FEATURE_LIST,contamination=0.15,experimental=True,n_estimators=1000,debug=False)
tt = round(time.time() - st,2)
print(f"Duration: {tt}s")




print("Showing...")
st = time.time()
# Plot the Data with matplotlib
show.show(data,mc_id,debug=True)
tt = round(time.time() - st,2)
print(f"Duration: {tt}s")