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


# Isolation Forest Function, also extracts selected Features from DataFrame
def isolation_forest(data:pd.DataFrame,features: list,n_estimators=100,contamination=0.01,sample_size=256,experimental=False,debug=False):
    # extract Features
    df = data[features]

    # Use Isolation Forest on DataFrame
    iso_forest = IsolationForest(n_estimators=n_estimators,
                                contamination=contamination,
                                max_samples=sample_size,
                                random_state=42)
    iso_forest.fit(df)

    # Ensure Indexing is correct and add anomaly score and anomaly true/false to the output dataframe
    o_df = df.loc[df.index].copy()
    o_df['anomaly_score'] = iso_forest.decision_function(df)
    o_df['anomaly'] = iso_forest.predict(df)

    # If in experimental mode, drop the row with the lowest anomaly score
    if experimental:
        o_df = o_df.drop(o_df["anomaly_score"].idxmin())

    # If in debug mode, enter a pseudo-shell to interact with the programm
    if debug:
        while True:
            try:
                cmd = input("python>")
                exec(cmd)
            except:
                pass
 
    # return finalised DataFrame
    return o_df

# Process the Dataframe with t-SNE first, the give it to the Isolation Forest function
def pre_process_i(data,features):
    # Extract wanted Features from DataFrame
    x = data[features]
    # Transform the DataFrame to a standardized format, for more equal computation between features
    x = StandardScaler().fit_transform(x)
    # Calculate t-sne with the dataframe, and save new DataFrame in variable sne_df
    sne = TSNE(n_components=2)
    sne_learned = sne.fit_transform(x)
    sne_df = pd.DataFrame(data=sne_learned,columns=["comp1","comp2"])
    # Run Isolation Forest over the new DataFrame
    o_df = isolation_forest(sne_df,["comp1","comp2"])

    # Return Data computed with t-sne then isolation forest
    return o_df

# Process the Data with K-means Clustering
def kmeans(data,features):
    # Extract wanted Features from DataFrame
    x = data[features]
    # Transform the DataFrame to a standardized format, for more equal computation between features
    x = StandardScaler().fit_transform(x)
    # Calculate k-means clusters with the DataFrame
    km = KMeans(init="random",n_clusters=3,n_init=100,max_iter=10000)
    km.fit(x)

    # Add cluster id to original DataFrame
    o_df = data.copy()
    o_df['cluster'] = km.labels_
    # Return DataFrame
    return o_df
    
# Use t-sne then k-means to get stable clusters, then calculate mean and stddev for every feature of every Cluster and return those values 
def combination(data,features,new=False,n_cluster=13,m_id=None):
    # Extract wanted Features from DataFrame
    x = data[features].copy()
    # Transform the DataFrame to a standardized format, for more equal computation between features
    x = StandardScaler().fit_transform(x)
    # Calculate t-sne with the dataframe, and save new DataFrame in variable sne_df
    sne = TSNE(n_components=2)
    sne_learned = sne.fit_transform(x)
    sne_df = pd.DataFrame(data=sne_learned,columns=["comp1","comp2"])

    # Plot the data from t-sne for more insight
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
    # Transform the DataFrame to a standardized format, for more equal computation between features
    y = StandardScaler().fit_transform(y)
    # Calculate k-means clusters with the DataFrame
    km = KMeans(init="random",n_clusters=n_cluster,n_init=100,max_iter=1000)
    km.fit(y)
    

    # Copy the data to avoid Fragmentation, add cluster id's, reset the index values and sort them again
    data = data.copy()
    data['cluster'] = km.labels_ 
    data = data.reset_index(drop=True)
    data = data.sort_values("bidirectional_first_seen_ms")
    # This step is for selecting in which cluster the Maclicious traffic is. 5 is a manually chosen value and if there are no id's
    # i probably forgot to change the user agent for the determination of malicious traffic
    try:
        mc_id = data.loc[m_id[5],"cluster"]
    except IndexError:
        print("No malicious ID found! Check your user agent")
        exit()
    # Append the feature list by cluster, since it is now also a valid feature and extract all wanted features from the DataFrame
    features.append("cluster")
    data = data[features].copy()
    
    # Calculate the mean and stddev of every feature in every Cluster and add them to a DataFrame
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
        
        # Write data to output DataFrame
        data = c_df.copy()


    # Return all computed Values
    return data,mc_id

 