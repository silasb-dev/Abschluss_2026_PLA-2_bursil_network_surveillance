#--------------------------------
# Author: Silas Burkhard
# Created: 26-06-04
# Last Changed: 26-06-04
# Description:
# Loads a Wireshark capture file,
# show graph with packet size per packet,
# highlight malicious Traffic
# (predefined)
#--------------------------------
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# Function to plot the given Dataframe with given Malicious Flows or Clusters
def show(df: pd.DataFrame,debug=False,show=True,v=True,experimental=False):
    # Index Anomalys for visualization
    df_anomaly = df[df["anomaly_score"] <= -0.02].copy()
    anomaly_id = df_anomaly.index.to_list()
    anomaly_id = np.where(df.index.isin(anomaly_id))[0].tolist()

    
    prognose = []

    if experimental:
        df.loc[df["anomaly_score"].idxmin(),"ignored"] = 1

    # Coloring:              Grey is normal, Red is malicious, Blue is anomaly and Purple is both malicious and suggested anomaly
    colors = ["grey"] * len(df)

    for i in anomaly_id:
        try:
            if df.loc[i,"ignored"] == 1:
                continue
        except KeyError:
            pass
        prognose.append(i)
        colors[i] = "blue"

    # If the debug option is set, open a pseudo-shell to interact with the enviroment
    if debug:
        while True:
            try:
                cmd = input("python>")
                exec(cmd)
            except:
                pass

    # Plot the data with the colors
    if show:
        plt.clf()
        plt.scatter(df.index,df["anomaly_score"],c=colors)
        try:
            plt.show()
        except:
            pass

    return colors, prognose

# Show Clusters
def c_show(df):
    #df_anomaly = df[df["anomaly"] == -1].copy()
    #anomaly_id = df_anomaly.index.to_list()
    #anomaly_id = np.where(df.index.isin(anomaly_id))[0].tolist()


    # Coloring
    colors = ["grey"] * len(df)


    # Plot the data with matplotlib
    plt.clf()
    plt.scatter(df.index,df["cluster"],c=colors)
    try:
        plt.show()
    except:
        pass

    return

# Old show funtion
def old_show(df: pd.DataFrame):
    # Select anomaly id's
    df_anomaly = df[df["anomaly"] == -1].copy()
    anomaly_id = df_anomaly.index.to_list()
    anomaly_id = np.where(df.index.isin(anomaly_id))[0].tolist()

    

    # Coloring
    colors = ["grey"] * len(df)

    for i in anomaly_id:
        colors[i] = "blue"
        print(i)


    # Plot the data with the colors
    plt.scatter(df.index,df["anomaly_score"],c=colors)
    try:
        plt.show()
    except:
        pass

    return