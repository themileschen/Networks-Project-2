'''
Basic network monitor using psutil and scapy with sending/receiving stats by application layer protocol 

network_monitor_3.py
ChatGPT

'''

from scapy.all import *
import time
import psutil   # to access system details and process utilities
from collections import defaultdict    # provides default values for missing keys 
from threading import Thread 
import os 
import pandas as pd
import matplotlib.pyplot as plt

# Status of program
program_running = True 

# Dictionary to store traffic by protocol
traffic_by_protocol = defaultdict(lambda: [0, 0])   # [Upload, Download]

# To store previous stats
traffic_df = None

# To display results
graph_df = pd.DataFrame()
counter = 0

# Get the MAC addresses of all network interfaces on the machine
ifaces = conf.ifaces
all_macs = {iface.mac for iface in ifaces.values()}
    # ifaces represents interface names (e.g. eth0) that are automatically initialized by Scapy 

# Port-to protocol mapping based on standard ports 
TCP_PROTOCOLS = {
    20: "FTP", 21: "FTP",
    23: "TELNET",
    25: "SMTP",
    80: "HTTP",
    110: "POP",
    161: "SNMP",
    443: "HTTPS",
}
UDP_PROTOCOLS = {
    53: "DNS",
    67: "DHCP", 68: "DHCP",
    69: "TFTP",
    123: "NTP",
    162: "SNMP",
}

# Returns the application-layer protocol (most of which operate on TCP or UDP in the transport layer)
def get_protocol_name(packet):
    if packet.haslayer(TCP):
        port = packet[TCP].dport if packet[TCP].dport in TCP_PROTOCOLS else packet[TCP].sport
        return TCP_PROTOCOLS.get(port, "Other TCP")
    elif packet.haslayer(UDP):
        port = packet[UDP].dport if packet[UDP].dport in UDP_PROTOCOLS else packet[UDP].sport
        return UDP_PROTOCOLS.get(port, "Other UDP")
    return "Non-TCP/UDP"
        
# Units of memory sizes
size = ['bytes', 'KB', 'MB', 'GB', 'TB']

# Function that returns bytes in a readable format
def getSize(bytes):
    for unit in size:
        if bytes < 1024:
            return f"{bytes:.1f}{unit}"
        bytes /= 1024

# Update upload and download traffic 
def process_packet(packet):
    protocol = get_protocol_name(packet)
    if packet.src in all_macs:
        # Source MAC address is our MAC address ==> outgoing
        traffic_by_protocol[protocol][0] += len(packet)
    else:
        # Incoming packet
        traffic_by_protocol[protocol][1] += len(packet)

# Print to DataFrame and save for graphing 
def printProtocols():
    global traffic_df
    global graph_df 
    global counter 
    counter += 1
    protocols = []  # Initialize list of protocols 
    for protocol, traffic in list(traffic_by_protocol.items()): # For each protocol
        addProtocol = {
            'Protocol': protocol, 'Total Sent': traffic[0], 
            'Total Received': traffic[1]
        }
        try:    # Calculate speeds
            addProtocol['Sending Speed'] = traffic[0] - traffic_df.at[protocol, 'Total Sent']
            addProtocol['Receiving Speed'] = traffic[1] - traffic_df.at[protocol, 'Total Received']
        except (KeyError, AttributeError):  # First time running
            addProtocol['Sending Speed'] = traffic[0]
            addProtocol['Receiving Speed'] = traffic[1]
        protocols.append(addProtocol)

        # For later display
        total = traffic[0] + traffic[1]
        graph_df.loc[counter, protocol] = total

    # Set up DataFrame and print 
    curr_df = pd.DataFrame(protocols)
    try:
        curr_df = curr_df.set_index('Protocol')
        curr_df['Total'] = curr_df['Total Sent'] + curr_df['Total Received']
        curr_df.sort_values('Total', inplace=True, ascending=False)
        curr_df = curr_df.drop('Total', axis=1)
    except KeyError as e:
        pass    # Empty DataFrame 
    printing_df = curr_df.copy()    # Copy to print 
    try:
        printing_df['Total Sent'] = printing_df['Total Sent'].apply(getSize)
        printing_df['Total Received'] = printing_df['Total Received'].apply(getSize)
        printing_df['Sending Speed'] = printing_df['Sending Speed'].apply(getSize).apply(lambda s: f"{s}/s")   # format: per second
        printing_df['Receiving Speed'] = printing_df['Receiving Speed'].apply(getSize).apply(lambda s: f"{s}/s") 
    except KeyError as e:
        pass    # Empty DataFrame 
    os.system('clear')
    print(printing_df.to_string())
    traffic_df = curr_df    # Update for future reference 

# Keep printing stats
def printStats():
    while program_running:
        time.sleep(1)   # Aids in calculating speed (e.g. KB/sec)
        printProtocols()

# Line graph 
def graphResults():
    plt.figure()
    for protocol in graph_df.columns:
        if 'TCP' not in protocol and 'UDP' not in protocol:  # Only plot application-layer protocols (not labeled 'Other TCP', etc.)
            plt.plot(graph_df.index, graph_df[protocol], label=protocol)
    plt.xlabel('Time (s)')
    plt.ylabel('Total Data Sent and Received (bytes)')
    plt.title('Total Data by Application Protocol')
    plt.legend()
    plt.show()

# Main
if __name__ == '__main__':
    printing_thread = Thread(target=printStats, daemon=True)
        # daemon: thread terminates automatically when main program exits
    printing_thread.start()

    # Start sniffing
    print('Started sniffing')
    try: 
        sniff(prn=process_packet, store=False)  # Don't store captured packets in memory
    except KeyboardInterrupt:
        pass
    finally:
        graphResults()
        program_running = False     # Whenever we exit sniff() function 
        printing_thread.join()
        
    

