#--------------------------------
# Author: Silas Burkhard
# Created: 26-06-18
# Last Changed: 26-06-18
# Description:
# Loads a Wireshark capture file,
# extract selected Features. 
#--------------------------------

import nfstream as nf
import numpy as np
import pandas as pd
import ipaddress
import time

class PacketFlow(nf.NFPlugin):
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

    def on_init(self, packet, flow):

        flow.udps.packet_inf = []
    
    def on_update(self, packet, flow):
        flow.udps.packet_inf.append([packet.src_ip,packet.dst_ip,packet.src_port,packet.dst_port,packet.protocol])


def start_stream(interface):
    return nf.NFStreamer(source=interface,statistical_analysis=True,udps=PacketFlow(),system_visibility_mode=True,performance_report=True,max_nflows=300)
    

# Load Pcap File, calculate additional Features and return
def extractor(stream,filter=True,dns=False):
    # Load Capture file to pandas Dataframe
    df = stream.to_pandas()


    # If filter option is set, drop all flows that are not HTTP, TLS or DNS
    if filter:
        df = df[df["application_name"].isin(["HTTP","TLS","DNS"])].copy()

    # Reset the index and sort the dataframe again
    df = df.reset_index(drop=True)
    df = df.sort_values("bidirectional_first_seen_ms",ignore_index=True)
    

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


    # Return df
    return df

# Loads a csv file with flows. Is much more efficient than the extractor function  
def l_file(file):
    # Read csv file
    df = pd.read_pickle("data.pkl")

    # reset index and sort rows
    df = df.reset_index(drop=True)
    df = df.sort_values("bidirectional_first_seen_ms")

    # If the user agent is set, use it to get the id's of malicious flows
    return df   