#--------------------------------
# Author: Silas Burkhard
# Created: 26-06-10
# Last Changed: 26-06-11
# Description:
# Main File to join
# other files togheter.
# extract features ->
# calculate iso Forest ->
# Return Data to analysis
#--------------------------------
from algorithm import i_forest_t_test
from parser import extract
from visualize import show
import pandas as pd
import time


def run():
    # PARAMETERS ######################################
    CAPTURE_FILE = "../captures/sliver_90k.pcapng"
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5205.266 Safari/537.36" # python-requests/2.34.2 python-requests/2.32.5
    FEATURE_LIST = ["time_since_prev_flow","dst2src_max_ps","dst2src_stddev_ps","protocol_id","src2dst_stddev_ps","src2dst_max_ps"]
    NEW_FEATURE_LIST = ["time_since_prev_flow_mean",
                        "dst2src_max_ps_mean",
                        "dst2src_stddev_ps_mean",
                        "protocol_id_mean",
                        "src2dst_stddev_ps_mean",
                        "src2dst_max_ps_mean"]
    ###################################################
    # Extract Features and the id's of the malicious traffic
    data, m_id = extract.extractor(CAPTURE_FILE,m_traffic_u_agent=USER_AGENT)
    # Use t-sne and then k-means clustering for better analysis
    data,mc_id,mc_info = i_forest_t_test.combination(data,FEATURE_LIST,new=True,m_id=m_id)
    #print(mc_info)
    FEATURE_LIST.append("cluster")
    # Use Isolation forest on the optimized data
    data = i_forest_t_test.isolation_forest(data,NEW_FEATURE_LIST,contamination=0.20,n_estimators=1000,debug=False)

    # Plot the Data with matplotlib
    cresult,_ = show.show(data,mc_id,debug=False,show=False,v=False,experimental=True)

    return cresult
