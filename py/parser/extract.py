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

# Load Pcap File, calculate additional Features and return
def extractor(file: str,m_traffic_u_agent=None,filter=True,dns=False):
    # Load Capture file to pandas Dataframe
    stream = nf.NFStreamer(source=file,statistical_analysis=True)
    df = stream.to_pandas(columns_to_anonymize=())


    # If filter option is set, drop all flows that are not HTTP, TLS or DNS
    if filter:
        df = df[df["application_name"].isin(["HTTP","TLS","DNS"])].copy()

    # Reset the index and sort the dataframe again
    df = df.reset_index(drop=True)
    df = df.sort_values("bidirectional_first_seen_ms")

    # if the dns option is not set, use the user agent to confirm malicious traffic. if it is set, use the dst and src ip
    if not dns:
        if m_traffic_u_agent != None:
            # Select malicious Traffic ID's
            df1 = df[df["user_agent"] == m_traffic_u_agent].copy()
            malicious_id = df1.index.to_list()
            malicious_id = np.where(df.index.isin(malicious_id))[0].tolist()
    else:
        df1 = df[(df["src_ip"] == "1.1.1.1") | (df["dst_ip"] == "1.1.1.1")]
        malicious_id = df1.index.to_list()
        malicious_id = np.where(df.index.isin(malicious_id))[0].tolist()

        print(df["src_ip"])
        print(df1)

    # Add Feature bidirectional first seen
    group_cols = ["src_ip","dst_ip","dst_port","protocol"]
    df["time_since_prev_flow"] = (df.groupby(group_cols)["bidirectional_first_seen_ms"].diff())
    df["time_since_prev_flow"] = df["time_since_prev_flow"].fillna(0)  

    # Add Feature IP as an Int
    df["ip_int"] = df["dst_ip"].apply(lambda x: int(ipaddress.ip_address(x)))

    # Add Feature correlation src2dst
    df["correlation_src2dst"] = (df["src2dst_bytes"] / df["dst2src_bytes"]).replace([np.inf, -np.inf],0)

    # Reconfigure Application Name Column
    u_proto = df['application_name'].unique()
    mapping = {
        protocol: i
        for i, protocol in enumerate(u_proto)
    }
    df['protocol_id'] = df['application_name'].map(mapping)



    # Return df and malicious traffic if wanted
    if m_traffic_u_agent != None:
        return df,malicious_id
    else:
        return df

# Loads a csv file with flows. Is much more efficient than the extractor function  
def l_file(file,m_traffic_u_agent=None,dns=False):
    # Read csv file
    df = pd.read_csv("data.csv")

    # reset index and sort rows
    df = df.reset_index(drop=True)
    df = df.sort_values("bidirectional_first_seen_ms")

    # If the user agent is set, use it to get the id's of malicious flows
    if m_traffic_u_agent != None:
        # Select malicious Traffic ID's
        df1 = df[df["user_agent"] == m_traffic_u_agent].copy()
        malicious_id = df1.index.to_list()
        malicious_id = np.where(df.index.isin(malicious_id))[0].tolist()

    # return the Dataframe and malicious id's if wanted
    if m_traffic_u_agent != None:
        return df,malicious_id
    else:
        return df   