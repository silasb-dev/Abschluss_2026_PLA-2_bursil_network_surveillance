#--------------------------------
# Author: Silas Burkhard
# Created: 26-06-05
# Last Changed: 26-06-05
# Description:
# Loads a Wireshark capture file,
# select wanted features,
# use either PCA or t-SNE for
# dimension reduction and 
# highlight malicious Traffic
# (predefined)
#--------------------------------

import nfstream as nf
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import ipaddress

from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE

# Select Algorithm to use
ALGORYTHM = "t-SNE"


# Features which i am using                    protocol id is application_name but as numbers
numerical_features = ["time_since_prev_flow","protocol_id","dst2src_max_ps","dst2src_stddev_ps","src2dst_stddev_ps","src2dst_max_ps"]

# Load Capture file to pandas Dataframe
#stream = nf.NFStreamer(source="captures/400k.pcapng",statistical_analysis=True)
#df = stream.to_pandas(columns_to_anonymize=())
df = pd.read_csv("data.csv")
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

# Reconfigure Application Name Column
u_proto = df['application_name'].unique()
mapping = {
    protocol: i
    for i, protocol in enumerate(u_proto)
}
df['protocol_id'] = df['application_name'].map(mapping)

x = df[numerical_features]
x = StandardScaler().fit_transform(x)
normalized = pd.DataFrame(x,columns=numerical_features)

if ALGORYTHM=="PCA":
    pca = PCA(n_components=2)
    pca_learned = pca.fit_transform(x)
    comp_df = pd.DataFrame(data=pca_learned,columns=["comp1","comp2"])
else:
    sne = TSNE(n_components=2)
    sne_learned = sne.fit_transform(x)
    comp_df = pd.DataFrame(data=sne_learned,columns=["comp1","comp2"])

colors = ["grey"] * len(comp_df)
for idx in malicious_id:
    colors[idx] = "red"


print("Showing...")
plt.scatter(comp_df["comp1"],comp_df["comp2"],c=colors)
plt.show()