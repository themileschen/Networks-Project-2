'''
Basic network monitor using psutil with sending/receiving stats 

https://pyseek.com/2022/10/create-a-network-traffic-monitor-using-python/
https://www.geeksforgeeks.org/psutil-module-in-python/
'''

import os   # functions for interacting with the OS 
import time
import psutil   # to access system details and process utilities
from prettytable import PrettyTable
from prettytable import DOUBLE_BORDER

# Units of memory sizes
size = ['bytes', 'KB', 'MB', 'GB', 'TB']

# Function that returns bytes in a readable format
def getSize(bytes):
    for unit in size:
        if bytes < 1024:
            return f"{bytes:.1f}{unit}"
        bytes /= 1024

# Prints the data on the terminal
def printData():
    # Create instance of PrettyTable class
    card = PrettyTable()
    card.set_style(DOUBLE_BORDER)
    # Column names of the table
    card.field_names = ['Total Received', 'Receiving', 'In Packet Dropping', 'Total Sent', 'Sending', 'Out Packet Dropping']
    # Add row to the table 
    card.add_row([f"{getSize(netStats2.bytes_recv)}", 
        f"{getSize(downloadStat)}/s", 
        f"{recPackLost:.2f}%", 
        f"{getSize(netStats2.bytes_sent)}", 
        f"{getSize(uploadStat)}/s",
        f"{outPackLost:.2f}%"])
    print(card)

# Get network I/O statistics as a namedtuple 
netStats1 = psutil.net_io_counters()

# Get data (bytes sent/recv, packets sent/recv, packets dropped incoming/outgoing)
dataSent = netStats1.bytes_sent
dataRecv = netStats1.bytes_recv
packetsSent = netStats1.packets_sent 
packetsRecv = netStats1.packets_recv
dropin = netStats1.dropin
dropout = netStats1.dropout 

# Get data continuously 
while True:
    time.sleep(1)   # delay for 2 seconds

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

    # Reset 
    dataSent = netStats2.bytes_sent
    dataRecv = netStats2.bytes_recv 
    packetsSent = netStats2.packets_sent 
    packetsRecv = netStats2.packets_recv
    dropin = netStats2.dropin
    dropout = netStats2.dropout 



