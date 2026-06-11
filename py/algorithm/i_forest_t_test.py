#--------------------------------
# Author: Silas Burkhard
# Created: 26-06-10
# Last Changed: 26-06-10
# Description:
# Uses the Isolation Forest
# Algorithm and returns
# the results
#--------------------------------

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.manifold import TSNE
from sklearn.cluster import KMeans

def isolation_forest(data:pd.DataFrame,features: list,n_estimators=100,contamination=0.01,sample_size=256,experimental=False,debug=False):
    df = data[features]

    iso_forest = IsolationForest(n_estimators=n_estimators,
                                contamination=contamination,
                                max_samples=sample_size,
                                random_state=42)
    iso_forest.fit(df)

    o_df = df.loc[df.index].copy()
    o_df['anomaly_score'] = iso_forest.decision_function(df)
    o_df['anomaly'] = iso_forest.predict(df)

    if experimental:
        o_df = o_df.drop(o_df["anomaly_score"].idxmin())

    if debug:
        while True:
            try:
                cmd = input("python>")
                exec(cmd)
            except:
                pass
 
    return o_df

def pre_process_i(data,features):
    x = data[features]
    x = StandardScaler().fit_transform(x)
    sne = TSNE(n_components=2)
    sne_learned = sne.fit_transform(x)
    sne_df = pd.DataFrame(data=sne_learned,columns=["comp1","comp2"])
    o_df = isolation_forest(sne_df,["comp1","comp2"])

    return o_df


def kmeans(data,features):
    x = data[features]
    x = StandardScaler().fit_transform(x)
    km = KMeans(init="random",n_clusters=3,n_init=100,max_iter=10000)
    km.fit(x)

    o_df = data.copy()
    o_df['cluster'] = km.labels_

    return o_df
    

def combination(data,features,new=False,n_cluster=13,m_id=None):
    x = data[features].copy()
    x = StandardScaler().fit_transform(x)
    sne = TSNE(n_components=2)
    sne_learned = sne.fit_transform(x)
    sne_df = pd.DataFrame(data=sne_learned,columns=["comp1","comp2"])

    """ try:
        import matplotlib.pyplot as plt
        colors = ["grey"] * len(sne_df)
        for i in m_id:
            colors[i] = "red"
        plt.scatter(sne_df["comp1"],sne_df["comp2"],c=colors)
        plt.show()
    except:
        pass """

    y = sne_df.copy()
    y = StandardScaler().fit_transform(y)
    km = KMeans(init="random",n_clusters=n_cluster,n_init=100,max_iter=1000)
    km.fit(y)
    


    data = data.copy()
    data['cluster'] = km.labels_ 
    data = data.reset_index(drop=True)
    data = data.sort_values("bidirectional_first_seen_ms")
    try:
        mc_id = data.loc[m_id[5],"cluster"]
    except IndexError:
        print("No malicious ID found! Check your user agent")
        exit()
    features.append("cluster")
    data = data[features].copy()

    
    pd.DataFrame()
    
    if new:
        c_df = pd.DataFrame()
        for c in range(n_cluster):
            cluster = data[data["cluster"] == c]
            cluster = cluster[["time_since_prev_flow","dst2src_max_ps","dst2src_stddev_ps","protocol_id","src2dst_stddev_ps","src2dst_max_ps"]].copy()
            mean = cluster.mean()
            stddev = cluster.std()
            for f in ["time_since_prev_flow","dst2src_max_ps","dst2src_stddev_ps","protocol_id","src2dst_stddev_ps","src2dst_max_ps"]:
                c_df.loc[c,f+"_mean"] = mean[f]
                c_df.loc[c,f+"_stddev"] = stddev[f]
        

        data = c_df.copy()


 
    return data,mc_id

 