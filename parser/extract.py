#--------------------------------
# Author: Silas Burkhard
# Created: 26-06-05
# Last Changed: 26-06-05
# Description:
# Loads a Wireshark capture file,
# extract selected Features.
# Optionaly get ID's of 
# malicious Traffic
# 
#--------------------------------

import nfstream as nf
import numpy as np
import pandas as pd
import ipaddress




# Features which i am using
numerical_features = ["bidirectional_duration_ms", "bidirectional_packets", "bidirectional_bytes","time_since_prev_flow","dst2src_max_ps","src2dst_max_ps", "src2dst_bytes","dst2src_bytes","src2dst_max_piat_ms","dst2src_max_piat_ms"]

# Load Capture file to pandas Dataframe
stream = nf.NFStreamer(source="captures/400k.pcapng",statistical_analysis=True)
df = stream.to_pandas(columns_to_anonymize=())
df = df.reset_index(drop=True)
df = df.sort_values("bidirectional_first_seen_ms")

# Select malicious Traffic ID's
df1 = df[df["user_agent"] == "python-requests/2.34.2"].copy()
malicious_id = df1["id"].to_list()
malicious_id = np.where(df["id"].isin(malicious_id))[0].tolist()

# Add Feature bidirectional first seen
group_cols = ["src_ip","dst_ip","dst_port","protocol"]
df["time_since_prev_flow"] = (df.groupby(group_cols)["bidirectional_first_seen_ms"].diff())
df["time_since_prev_flow"] = df["time_since_prev_flow"].fillna(0)

# Add Feature IP as an Int
df["ip_int"] = df["dst_ip"].apply(lambda x: int(ipaddress.ip_address(x)))

# Add Feature correlation src2dst
df["correlation_src2dst"] = (df["src2dst_bytes"] / df["dst2src_bytes"]).replace([np.inf, -np.inf],0)

def extractor(file: str,features: list,m_traffic_u_agent=None):
    # Load Capture file to pandas Dataframe
    stream = nf.NFStreamer(source=file,statistical_analysis=True)
    df = stream.to_pandas(columns_to_anonymize=())
    df = df.reset_index(drop=True)
    df = df.sort_values("bidirectional_first_seen_ms") 

    if m_traffic_u_agent != None:
        # Select malicious Traffic ID's
        df1 = df[df["user_agent"] == m_traffic_u_agent].copy()
        malicious_id = df1["id"].to_list()
        malicious_id = np.where(df["id"].isin(malicious_id))[0].tolist()

    # Add Feature bidirectional first seen
    group_cols = ["src_ip","dst_ip","dst_port","protocol"]
    df["time_since_prev_flow"] = (df.groupby(group_cols)["bidirectional_first_seen_ms"].diff())
    df["time_since_prev_flow"] = df["time_since_prev_flow"].fillna(0)  

    # Add Feature IP as an Int
    df["ip_int"] = df["dst_ip"].apply(lambda x: int(ipaddress.ip_address(x)))

    # Add Feature correlation src2dst
    df["correlation_src2dst"] = (df["src2dst_bytes"] / df["dst2src_bytes"]).replace([np.inf, -np.inf],0)

    if m_traffic_u_agent != None:
        return df,malicious_id
    else:
        return df