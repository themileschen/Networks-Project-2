'''
Basic network monitor using psutil with sending/receiving stats by network interface

network_monitor_1.py
https://thepythoncode.com/article/make-a-network-usage-monitor-in-python
'''

import os   # functions for interacting with the OS 
import time
import psutil   # to access system details and process utilities
import pandas as pd 

# Units of memory sizes
size = ['bytes', 'KB', 'MB', 'GB', 'TB']

# Function that returns bytes in a readable format
def getSize(bytes):
    for unit in size:
        if bytes < 1024:
            return f"{bytes:.1f}{unit}"
        bytes /= 1024

# Get network I/O statistics as a namedtuple 
netStats1 = psutil.net_io_counters(pernic=True)    # pernic=True: per interface

# Get data continuously
while True:
    time.sleep(1)   # delay for 1 second

    # Get network I/O stats again to count the sending and receiving speed
    netStats2 = psutil.net_io_counters(pernic=True)

    # Initialize the data to gather (as a list of dicts)
    data = []

    # Upload/sending and receiving/download speeds
    for iface, iface_io in netStats1.items():
        uploadStat = netStats2[iface].bytes_sent - iface_io.bytes_sent 
        downloadStat = netStats2[iface].bytes_recv - iface_io.bytes_recv 
        data.append({
            'Interface': iface, 
            'Total Received': getSize(netStats2[iface].bytes_recv),
            'Receiving': f"{getSize(downloadStat)}/s",
            'Total Sent': getSize(netStats2[iface].bytes_sent),
            'Sending': f"{getSize(uploadStat)}/s"
        })

    # Reset 
    netStats1 = netStats2

    # Construct DataFrame with columns sorted 
    df = pd.DataFrame(data)
    df.sort_values('Total Received', inplace=True, ascending=False)

    # Clear terminal and print
    os.system('clear')
    print(df.to_string(index=False))