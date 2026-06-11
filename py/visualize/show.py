import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

def show(df: pd.DataFrame,m_ids=None,debug=False):
    df_anomaly = df[df["anomaly"] == -1].copy()
    anomaly_id = df_anomaly.index.to_list()
    anomaly_id = np.where(df.index.isin(anomaly_id))[0].tolist()

    m_ids = df.index.get_loc(m_ids)

    print(df.iloc[m_ids])

    # Coloring
    colors = ["grey"] * len(df)
    
    colors[m_ids] = "red"
    for i in anomaly_id:
        if colors[i] == "red":
            colors[i] = "purple"
        else:
            colors[i] = "blue"

    if debug:
        while True:
            try:
                cmd = input("python>")
                exec(cmd)
            except:
                pass


    plt.clf()
    plt.scatter(df.index,df["anomaly_score"],c=colors)
    try:
        plt.show()
    except:
        pass

    return

def c_show(df,m_ids=None):
    #df_anomaly = df[df["anomaly"] == -1].copy()
    #anomaly_id = df_anomaly.index.to_list()
    #anomaly_id = np.where(df.index.isin(anomaly_id))[0].tolist()


    # Coloring
    colors = ["grey"] * len(df)
    for i in m_ids:
        colors[i] = "red"

    plt.clf()
    plt.scatter(df.index,df["cluster"],c=colors)
    try:
        plt.show()
    except:
        pass

    return


def old_show(df: pd.DataFrame,m_ids=None):
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



    plt.scatter(df.index,df["anomaly_score"],c=colors)
    try:
        plt.show()
    except:
        pass

    return