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
import matplotlib.pyplot as plt

from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE




# Features which i am using
numerical_features = ["time_since_prev_flow","bidirectional_duration_ms","bidirectional_mean_piat_ms"]

#stream = nf.NFStreamer(source="../captures/400k.pcapng",statistical_analysis=True,max_nflows=150)
#df = stream.to_pandas(columns_to_anonymize=())
df = pd.read_csv("data.csv")
df = df.reset_index(drop=True)
df = df.sort_values("bidirectional_first_seen_ms")

# Select malicious flow id's
df1 = df[df["user_agent"] == "python-requests/2.34.2"].copy()
malicious_id = df1.index.to_list()
malicious_id = np.where(df.index.isin(malicious_id))[0].tolist()

# Columns by which a similar flow is identified. used for time_since_prev_flow feature
group_cols = ["src_ip","dst_ip","dst_port","protocol"]
# Calculate time_since_prev_flow feature
df["time_since_prev_flow"] = (df.groupby(group_cols)["bidirectional_first_seen_ms"].diff())
df["time_since_prev_flow"] = df["time_since_prev_flow"].fillna(0)

# Create color array for showing malicious Flows
colors = ["grey"] * len(df)
for idx in malicious_id:
    colors[idx] = "red"


# Plot every flow with id and a feature to inspect
plt.scatter(df["id"],df["bidirectional_max_piat_ms"],c=colors)
plt.show()

