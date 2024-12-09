'''
Basic network monitor and visualization using psutil with sending/receiving stats and socket connections

https://pyseek.com/2022/10/create-a-network-traffic-monitor-using-python/
https://www.geeksforgeeks.org/psutil-module-in-python/
'''

import os   # functions for interacting with the OS 
import time
import psutil   # to access system details and process utilities
from prettytable import PrettyTable
import pandas as pd 
import matplotlib.pyplot as plt
import sys  # command line args 
from datetime import datetime, timedelta

# Get the time from user 
if len(sys.argv) != 2:
    print("Usage: python network_monitor_1.py <time of data collection in seconds>")
    exit(1)
TIME = int(sys.argv[1])

# Get program start time and end time
START_TIME = datetime.now()
END_TIME = START_TIME + timedelta(seconds=TIME)

# Units of memory sizes
size = ['bytes', 'KB', 'MB', 'GB', 'TB']

# Create empty DataFrames 
inout_df = pd.DataFrame(columns=['Total Received (bytes)', 'Receiving (bytes/sec)', 'In Packet Dropping (%)',
                                 'Total Sent (bytes)', 'Sending (bytes/sec)', 'Out Packet Dropping (%)'])
socket_df = pd.DataFrame(columns=['Total', 'inet', 'TCP', 'UDP'])

# Function that returns bytes in a readable format
def getSize(bytes):
    for unit in size:
        if bytes < 1024:
            return f"{bytes:.1f}{unit}"
        bytes /= 1024

# Prints the network data on the terminal
def printData():
    # Create instance of PrettyTable class
    card = PrettyTable()
    # Column names of the table
    card.field_names = ['Total Received', 'Receiving', 'In Packet Dropping', 
                        'Total Sent', 'Sending', 'Out Packet Dropping']
    # Add row to the table 
    card.add_row([f"{getSize(netStats2.bytes_recv - RECV_START)}", 
        f"{getSize(downloadStat)}/s", 
        f"{recPackLost:.2f}%", 
        f"{getSize(netStats2.bytes_sent - SENT_START)}", 
        f"{getSize(uploadStat)}/s",
        f"{outPackLost:.2f}%"])
    print(card)
    # Add info to end of DataFrame
    inout_df.loc[len(inout_df)] = [
        netStats2.bytes_recv - RECV_START,
        downloadStat,
        f"{recPackLost:.2f}",
        netStats2.bytes_sent - SENT_START,
        uploadStat,
        f"{outPackLost:.2f}"
    ]

# Prints socket data on the terminal
def printSocketData():
    totalSocketInfo = psutil.net_connections()
    inetSocketInfo = psutil.net_connections(kind='inet')
    TCPsocketInfo = psutil.net_connections(kind='tcp')
    UDPsocketInfo = psutil.net_connections(kind='udp')
    card2 = PrettyTable()
    card2.field_names = ['Total Socket Connections', 'inet', 'TCP', 'UDP']
    card2.add_row([f"{len(totalSocketInfo)}",
        f"{len(inetSocketInfo)}",
        f"{len(TCPsocketInfo)}",
        f"{len(UDPsocketInfo)}"])
    print(card2)
    # for conn in socketInfo:
    #     print(conn)
    socket_df.loc[len(socket_df)] = [
        len(totalSocketInfo),
        len(inetSocketInfo),
        len(TCPsocketInfo),
        len(UDPsocketInfo)
    ]


# Get network I/O statistics as a namedtuple 
netStats1 = psutil.net_io_counters()

# Get data (bytes sent/recv, packets sent/recv, packets dropped incoming/outgoing)
dataSent = netStats1.bytes_sent
dataRecv = netStats1.bytes_recv
packetsSent = netStats1.packets_sent 
packetsRecv = netStats1.packets_recv
dropin = netStats1.dropin
dropout = netStats1.dropout 

# Total data sent and received (measured at start of program) 
SENT_START = dataSent
RECV_START = dataRecv 

# Get data continuously 
# while True:

# Get data for the user-defined time
while (datetime.now() < END_TIME):
    time.sleep(1)   # delay for 1 second

    # Clear terminal
    os.system('clear')

    # Get network I/O stats again to count the sending and receiving speed
    netStats2 = psutil.net_io_counters()

    # Upload/sending and receiving/download speeds
    uploadStat = netStats2.bytes_sent - dataSent
    downloadStat = netStats2.bytes_recv - dataRecv 
    # Packet drop rates 
    if ((netStats2.packets_recv - packetsRecv) != 0):
        recPackLost = ((netStats2.dropin - dropin) / (netStats2.packets_recv - packetsRecv)) * 100.0
    else:
        recPackLost = 0.0
    if ((netStats2.packets_sent - packetsSent) != 0):
        outPackLost = ((netStats2.dropout - dropout) / (netStats2.packets_sent - packetsSent)) * 100.0
    else:
        outPackLost = 0.0

    printData()

    printSocketData()

    # Reset 
    dataSent = netStats2.bytes_sent
    dataRecv = netStats2.bytes_recv 
    packetsSent = netStats2.packets_sent 
    packetsRecv = netStats2.packets_recv
    dropin = netStats2.dropin
    dropout = netStats2.dropout 

# Show DataFrames (summary of tabular data)
print(inout_df)
print(socket_df)

# Plot graphs 

plt.figure()
plt.plot(inout_df.index, inout_df['Total Received (bytes)'], label = 'Total Received')
plt.plot(inout_df.index, inout_df['Total Sent (bytes)'], label = 'Total Sent')
plt.xlabel('Time')
plt.ylabel('Data (bytes)')
plt.title('Total Data Sent and Received')
plt.legend()

plt.figure()
plt.plot(inout_df.index, inout_df['Receiving (bytes/sec)'], label = 'Receiving')
plt.plot(inout_df.index, inout_df['Sending (bytes/sec)'], label = 'Sending')
plt.xlabel('Time')
plt.ylabel('Bytes/sec')
plt.title('Sending and Receiving Rates')
plt.legend()

plt.figure()
plt.plot(socket_df.index, socket_df['Total'], label = 'Total')
plt.plot(socket_df.index, socket_df['inet'], label = 'inet')
plt.plot(socket_df.index, socket_df['TCP'], label = 'TCP')
plt.plot(socket_df.index, socket_df['UDP'], label = 'UDP')
plt.xlabel('Time')
plt.ylabel('Number of Connections')
plt.title('Socket Connections')
plt.legend()

plt.show()