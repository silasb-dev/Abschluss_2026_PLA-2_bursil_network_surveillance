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
import numpy as np
import time
import ast

# PARAMETERS ######################################
CAPTURE_FILE = "../captures/100k.pcapng"
USER_AGENT = "python-requests/2.32.5" # python-requests/2.34.2 python-requests/2.32.5 Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5205.266 Safari/537.36
FEATURE_LIST = ["time_since_prev_flow","dst2src_max_ps","dst2src_stddev_ps","protocol_id","src2dst_stddev_ps","src2dst_max_ps"]
NEW_FEATURE_LIST = ["time_since_prev_flow_mean",
                    "dst2src_max_ps_mean",
                    "dst2src_stddev_ps_mean",
                    "protocol_id_mean",
                    "src2dst_stddev_ps_mean",
                    "src2dst_max_ps_mean"]
###################################################
def flatten_extend(matrix):
     flat_list = []
     for row in matrix:
         flat_list.extend(row)
     return flat_list


def packet_return(suggested_df:pd.DataFrame,prognose):
    
    

    print(prognose)
    packet_list = []
    for i in prognose:
        packet = ast.literal_eval(suggested_df.loc[i,"udps.packet_inf"])
        packet_list.append([list(x) for x in dict.fromkeys(map(tuple, packet))][0])

    new_df = pd.DataFrame(columns=["packet_data"])
    packet_list.sort()
    for packet in packet_list:
        new_df.at[len(new_df),"packet_data"] = packet


    new_df["Filter"] = new_df["packet_data"].apply(lambda x: f"ip.addr == {x[0]} && ip.addr == {x[1]} && tcp.port == {x[2]} && tcp.port == {x[3]}")
    new_df.to_excel("out.xlsx")
    print("Saved to File: out.xlsx")

def select_prognose(data_list,prognose):
    new_list = []
    for i in data_list:
        if i[1] in prognose:
            new_list.append(i)

    
    return new_list


print("Extracting...")
st = time.time()
# Extract Features and the id's of the malicious traffic
raw_data, m_id = extract.l_file(CAPTURE_FILE,m_traffic_u_agent=USER_AGENT)
tt = round(time.time() - st,2)
print(f"Duration: {tt}s")
raw_data.to_pkl("data.pkl")
print("Isolating...")
st = time.time()
# Use t-sne and then k-means clustering for better analysis
data,mc_id,mc_info = i_forest_t_test.combination(raw_data,FEATURE_LIST,new=True,m_id=m_id)
FEATURE_LIST.append("cluster")
# Use Isolation forest on the optimized data
data = i_forest_t_test.isolation_forest(data,NEW_FEATURE_LIST,contamination=0.20,n_estimators=1000,debug=False)
tt = round(time.time() - st,2)
print(f"Duration: {tt}s")




print("Showing...")
st = time.time()
# Plot the Data with matplotlib
_,prognose = show.show(data,mc_id,debug=False,experimental=False)
tt = round(time.time() - st,2)
print(f"Duration: {tt}s")

prognose = select_prognose(mc_info,prognose)
flat_prog = flatten_extend(prognose)[::2]



packet_return(raw_data,flat_prog)