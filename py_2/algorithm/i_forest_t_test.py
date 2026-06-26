#--------------------------------
# Author: Silas Burkhard
# Created: 26-06-10
# Last Changed: 26-06-10
# Description:
# Uses the Isolation Forest
# Algorithm and returns
# the results
#--------------------------------

import math
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.manifold import TSNE
from sklearn.cluster import KMeans

# Function to calculate Density of Cluster based on 2D Distance
def calculate_density(d_points,c_points,c_id):
    n_cluster = max(c_id)
    cluster_density = []

    

    for cluster_id in range(n_cluster+1):
        points = []
        for i in range(len(d_points)):
            if c_id[i] == cluster_id:
                points.append(d_points[i])

        distance = 0
        for i in points:
            distance += math.sqrt((i[0]-c_points[cluster_id][0])**2+(i[0]-c_points[cluster_id][0])**2)
        distance = distance / len(points)
        cluster_density.append(distance)

    return cluster_density
        

# Isolation Forest Function, also extracts selected Features from DataFrame
def isolation_forest(data:pd.DataFrame,features: list,n_estimators=100,contamination=0.01,sample_size=256,debug=False):
    # extract Features
    features.append('density')
    df = data[features]

    
    # Use Isolation Forest on DataFrame
    iso_forest = IsolationForest(n_estimators=n_estimators,
                                contamination=contamination,
                                max_samples=len(df))
    iso_forest.fit(df)

    # Ensure Indexing is correct and add anomaly score and anomaly true/false to the output dataframe
    o_df = df.loc[df.index].copy()
    o_df['anomaly_score'] = iso_forest.decision_function(df)
    o_df['anomaly'] = iso_forest.predict(df)



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
def pre_process_i(data,features,v=True):
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
def combination(data,features,new=False,n_cluster=10,v=True):
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
    data = data.sort_values("bidirectional_first_seen_ms",ignore_index=True)


    try:
        import matplotlib.pyplot as plt
        plt.clf()
        colors = ["grey"] * len(sne_df)

        c_data = y
        c_data = [list(col) for col in zip(*c_data)]
        plt.scatter(c_data[0],c_data[1],c=colors)
        c_center = km.cluster_centers_
        c_center = [list(col) for col in zip(*c_center)]
        for i in range(len(c_center[0])):
            plt.scatter(c_center[0][i],c_center[1][i],color="green",marker="$"+str(i)+"$")
        plt.show()
    except KeyboardInterrupt:
        pass
    
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
        return_data = c_df.copy()
        return_data['density'] = calculate_density(y,km.cluster_centers_,km.labels_)
        
        # Create an Array with Correlation between Cluster and Flow
        flow2cluster = []
        for index,flow in enumerate(data["cluster"]):
            flow2cluster.append((index,flow))
 

    # Return all computed Values
    return return_data,flow2cluster

 