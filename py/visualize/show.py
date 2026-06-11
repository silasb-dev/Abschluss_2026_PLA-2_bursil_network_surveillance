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
def show(df: pd.DataFrame,m_ids=None,debug=False):
    # Index Anomalys for visualization
    df_anomaly = df[df["anomaly"] == -1].copy()
    anomaly_id = df_anomaly.index.to_list()
    anomaly_id = np.where(df.index.isin(anomaly_id))[0].tolist()

    # Update malicious id's to match positional id's
    m_ids = df.index.get_loc(m_ids)
    print(df.iloc[m_ids])

    # Coloring:              Grey is normal, Red is malicious, Blue is anomaly and Purple is both malicious and suggested anomaly
    colors = ["grey"] * len(df)
    colors[m_ids] = "red"
    for i in anomaly_id:
        if colors[i] == "red":
            colors[i] = "purple"
        else:
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
    plt.clf()
    plt.scatter(df.index,df["anomaly_score"],c=colors)
    try:
        plt.show()
    except:
        pass

    return

# Show Clusters
def c_show(df,m_ids=None):
    #df_anomaly = df[df["anomaly"] == -1].copy()
    #anomaly_id = df_anomaly.index.to_list()
    #anomaly_id = np.where(df.index.isin(anomaly_id))[0].tolist()


    # Coloring
    colors = ["grey"] * len(df)
    for i in m_ids:
        colors[i] = "red"

    # Plot the data with matplotlib
    plt.clf()
    plt.scatter(df.index,df["cluster"],c=colors)
    try:
        plt.show()
    except:
        pass

    return

# Old show funtion
def old_show(df: pd.DataFrame,m_ids=None):
    # Select anomaly id's
    df_anomaly = df[df["anomaly"] == -1].copy()
    anomaly_id = df_anomaly.index.to_list()
    anomaly_id = np.where(df.index.isin(anomaly_id))[0].tolist()

    

    # Coloring
    colors = ["grey"] * len(df)
    for i in m_ids:
        try:
            colors[i] = "red"
        except:
            pass
    for i in anomaly_id:
        if colors[i] == "red":
            colors[i] = "purple"
        else:
            colors[i] = "blue"


    # Plot the data with the colors
    plt.scatter(df.index,df["anomaly_score"],c=colors)
    try:
        plt.show()
    except:
        pass

    return