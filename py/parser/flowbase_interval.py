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

from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA





# Select Features to use
numerical_features = ["src_port", "dst_port", "protocol", "bidirectional_first_seen_ms", "bidirectional_duration_ms", "bidirectional_packets", "bidirectional_bytes", "bidirectional_min_ps", "bidirectional_mean_ps", "bidirectional_stddev_ps", "bidirectional_max_ps","bidirectional_min_piat_ms", "bidirectional_mean_piat_ms", "bidirectional_stddev_piat_ms", "bidirectional_max_piat_ms", "src2dst_min_piat_ms", "src2dst_mean_piat_ms", "src2dst_stddev_piat_ms", "src2dst_max_piat_ms", "dst2src_min_piat_ms", "dst2src_mean_piat_ms", "dst2src_stddev_piat_ms", "dst2src_max_piat_ms"]

stream = nf.NFStreamer(source="captures/400k.pcapng",statistical_analysis=True)
df = stream.to_pandas(columns_to_anonymize=())
df = df.sort_values("bidirectional_first_seen_ms")
df = df.reset_index(drop=True)


# Grab ID's of malicious Traffic
df1 = df[df["user_agent"] == "python-requests/2.34.2"].copy()
malicious_id = df1["id"].to_list()
malicious_id = np.where(df["id"].isin(malicious_id))[0].tolist()

# columns that define a "similar" flow
group_cols = [
    "src_ip",
    "dst_ip",
    "dst_port",
    "protocol"
]

# time since previous similar flow
df["time_since_prev_flow"] = (
    df.groupby(group_cols)["bidirectional_first_seen_ms"]
      .diff()
)


# Apply Coloring
colors = ["grey"] * len(df)
for idx in malicious_id:
    colors[idx] = "red"

df.plot(x="id",y="time_since_prev_flow_ms",kind="scatter")
plt.scatter(df["id"],df["time_since_prev_flow_ms"],c=colors)
plt.show()


exit


x = df[numerical_features]
x = StandardScaler().fit_transform(x)
normalized = pd.DataFrame(x,columns=numerical_features)

pca = PCA(n_components=2)
pca_learned = pca.fit_transform(x)
pca_df = pd.DataFrame(data=pca_learned,columns=["comp1","comp2"])

colors = ["grey"] * len(pca_df)
for idx in [2, 42, 74, 410, 88, 110, 381, 530, 316, 533, 186, 537, 464, 538, 243, 466, 544, 390, 319, 244]:
    colors[idx] = "red"

print(len(colors))


plt.scatter(pca_df["comp1"],pca_df["comp2"],c=colors)
plt.show()