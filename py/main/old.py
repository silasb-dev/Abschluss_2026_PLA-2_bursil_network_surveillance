from algorithm import i_forest_t_test
from parser import extract
from visualize import show
import pandas as pd
import time

# PARAMETERS ######################################
CAPTURE_FILE = "../captures/400k.pcapng"
USER_AGENT = "python-requests/2.34.2"
FEATURE_LIST = ["bidirectional_first_seen_ms", "bidirectional_last_seen_ms", "bidirectional_duration_ms", "bidirectional_packets", "bidirectional_bytes", "src2dst_first_seen_ms", "src2dst_last_seen_ms", "src2dst_duration_ms", "src2dst_packets", "src2dst_bytes", "dst2src_first_seen_ms", "dst2src_last_seen_ms", "dst2src_duration_ms", "dst2src_packets", "dst2src_bytes", "bidirectional_min_ps", "bidirectional_mean_ps", "bidirectional_stddev_ps", "bidirectional_max_ps", "src2dst_min_ps", "src2dst_mean_ps", "src2dst_stddev_ps", "src2dst_max_ps", "dst2src_min_ps", "dst2src_mean_ps", "dst2src_stddev_ps", "dst2src_max_ps", "bidirectional_min_piat_ms", "bidirectional_mean_piat_ms", "bidirectional_stddev_piat_ms", "bidirectional_max_piat_ms", "src2dst_min_piat_ms", "src2dst_mean_piat_ms", "src2dst_stddev_piat_ms", "src2dst_max_piat_ms", "dst2src_min_piat_ms", "dst2src_mean_piat_ms", "dst2src_stddev_piat_ms", "dst2src_max_piat_ms"]
###################################################

print("Extracting...")
st = time.time()
data, m_id = extract.extractor(CAPTURE_FILE,m_traffic_u_agent=USER_AGENT)
tt = round(time.time() - st,2)
print(f"Duration: {tt}s")

print("Isolating...")
st = time.time()
data = i_forest_t_test.isolation_forest(data,FEATURE_LIST,contamination=0.05,experimental=True,n_estimators=100)
tt = round(time.time() - st,2)
print(f"Duration: {tt}s")




print("Showing...")
st = time.time()
show.old_show(data,m_id)
tt = round(time.time() - st,2)
print(f"Duration: {tt}s")