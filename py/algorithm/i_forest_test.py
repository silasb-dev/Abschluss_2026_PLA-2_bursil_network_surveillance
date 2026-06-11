# Tutorial File from:
# https://www.datacamp.com/tutorial/isolation-forest
#
# I used this file to get familiar with the Isolation forest algorithm
#

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

from sklearn.ensemble import IsolationForest
from ucimlrepo import fetch_ucirepo

# Fetch test data
air_quality = fetch_ucirepo(id=360)

data = air_quality.data.features
# Features in this file are df in my other files. features variables in other file contain a list of features to use, not the df
features = data[['CO(GT)', 'C6H6(GT)', 'NOx(GT)', 'NO2(GT)']]

# Replace and drop NaN values
features = features.replace(-200, np.nan)
features = features.dropna()
# show info of df
features.info()

# Parameters
n_estimators = 100  # Number of trees
contamination = 0.01  # Expected proportion of anomalies
sample_size = 256  # Number of samples used to train each tree

# Use Isolation Forest on the data
iso_forest = IsolationForest(n_estimators=n_estimators,
                            contamination=contamination,
                            max_samples=sample_size,
                            random_state=42)
iso_forest.fit(features)

# Add the anomaly score and anomaly true/false feature to the DataFrame
data = data.loc[features.index].copy()
data['anomaly_score'] = iso_forest.decision_function(features)
data['anomaly'] = iso_forest.predict(features)

data['anomaly'].value_counts()


# Visualization of the results
plt.figure(figsize=(10, 5))

# Plot normal instances
normal = data[data['anomaly'] == 1]
plt.scatter(normal.index, normal['anomaly_score'], label='Normal')

print(data["anomaly"].head())

# Plot anomalies
anomalies = data[data['anomaly'] == -1]
plt.scatter(anomalies.index, anomalies['anomaly_score'], label='Anomaly')
plt.xlabel("Instance")
plt.ylabel("Anomaly Score")
plt.legend()
plt.show()