'''
Basic network monitor using psutil and scapy with sending/receiving stats by process, including hogging flag

network_monitor_2.py
https://thepythoncode.com/article/make-a-network-usage-monitor-in-python

'''

from scapy.all import *
import os   # functions for interacting with the OS 
import time
import psutil   # to access system details and process utilities
import pandas as pd 
from collections import defaultdict    # provides default values for missing keys 
from threading import Thread 
from datetime import datetime 
import sys  # command line args 

# Get the threshold from user (or use default)
if len(sys.argv) != 2:
    BANDWIDTH = 0.5 # Default: if one process is using more than 50% of the total used bandwidth, it is "hogging"
elif (float(sys.argv[1]) < 0) | (float(sys.argv[1]) > 1):
    print("Threshold must be a proportion between 0 and 1")
    exit(1)
else:
    BANDWIDTH = float(sys.argv[1])

# Get the MAC addresses of all network interfaces on the machine
ifaces = conf.ifaces
all_macs = {iface.mac for iface in ifaces.values()}
    # ifaces represents interface names (e.g. eth0) that are automatically initialized by Scapy 

# Dictionary to map each connection (port on TCP/UDP layer) to its corresponding PID 
connection_to_pid = {}

# Dictionary to map each PID to total upload/download traffic
pid_to_traffic = defaultdict(lambda: [0, 0])

# DataFrame to keep track of previous traffic stats
traffic_df = None

# Status of program
program_running = True 

# Units of memory sizes
size = ['bytes', 'KB', 'MB', 'GB', 'TB']

# Function that returns bytes in a readable format
def getSize(bytes):
    for unit in size:
        if bytes < 1024:
            return f"{bytes:.1f}{unit}"
        bytes /= 1024

# Update upload and download traffic 
    # Get packet ports 
    # Get corresponding PID 
    # Update traffic data 
def process_packet(packet):
    global pid_to_traffic 
    try:
        # Get packet source and destination IP addresses and ports
        packet_connection = (packet.sport, packet.dport)
    except (AttributeError, IndexError):
        pass    # Packet may not have TCP/UDP layers 
    else:   # Executes only if no exception occurs in the try block 
        # Get PID responsible for this connection from the connection_to_pid dictionary
        packet_pid = connection_to_pid.get(packet_connection)
        if packet_pid:  # Update total traffic for the process
            if packet.src in all_macs:
                # Source MAC address is our MAC address ==> outgoing
                pid_to_traffic[packet_pid][0] += len(packet)
            else:
                # Incoming packet
                pid_to_traffic[packet_pid][1] += len(packet)

# Listens for connections and adds them to connection_to_pid 
    # Assign PID to ports 
def get_connections():
    global connection_to_pid
    while program_running:
        # Use psutil to grab each connection's ports and PID 
        for c in psutil.net_connections():
            if c.laddr and c.raddr and c.pid:
                # If local address, remote address, and PID are in the connection, add to dictionary
                connection_to_pid[(c.laddr.port, c.raddr.port)] = c.pid 
                connection_to_pid[(c.raddr.port, c.laddr.port)] = c.pid 
        time.sleep(1)   # Sleep for a second

# Iterate over process dictionary 
# Use traffic_df to get previous total usage and calculate current speed
# Append the process to processes list and convert to DataFrame for printing
def print_pid_to_traffic():
    global traffic_df
    processes = []  # Initialize list of processes
    total_bandwidth = 0     # Total current bandwidth consumed 
    process_bandwidth = pd.DataFrame(columns=['pid', 'bandwidth'])  # Current bandwidth consumed 
    for pid, traffic in list(pid_to_traffic.items()):   # list: create static items to iterate (prevent concurrent thread Runtime error)
        # pid is integer; traffic is a list of total upload and download size
        try:
            p = psutil.Process(pid)     # Get process object 
        except psutil.NoSuchProcess:    # Process not found
            continue
        name = p.name()     # Get process name
        # Get time the packet was spawned
        try:
            create_time = datetime.fromtimestamp(p.create_time())
        except OSError:
            # System processes, using boot time instead
            create_time = datetime.fromtimestamp(psutil.boot_time())
        # Construct dictionary to store process info
        process = {
            'pid': pid, 'name': name, 'create_time': create_time, 
            'Upload': traffic[0], 'Download': traffic[1], 'Bandwidth Hog': False
        }
        try:
            # Calculate upload and download speeds (subtract old stats)
            process['Upload Speed'] = traffic[0] - traffic_df.at[pid, 'Upload']            
            process['Download Speed'] = traffic[1] - traffic_df.at[pid, 'Download']
        except (KeyError, AttributeError):
            # If first time running function, the speed is just the current traffic
            process['Upload Speed'] = traffic[0]
            process['Download Speed'] = traffic[1]
        # Update bandwidth metrics 
        current_bandwidth = process['Upload Speed'] + process['Download Speed']
        total_bandwidth = total_bandwidth + current_bandwidth
        process_bandwidth.loc[len(process_bandwidth)] = [pid, current_bandwidth]
        processes.append(process)   # Append to list 
    # Set up DataFrame
    df = pd.DataFrame(processes)  
    try:
        df = df.set_index('pid')
        df['Total'] = df['Download'] + df['Upload']
        df.sort_values('Total', inplace=True, ascending=False)  # Sort by total traffic 
        df = df.drop('Total', axis=1)   # Don't print total column
    except KeyError as e:
        pass    # DataFrame empty

    # Update bandwidth hogs 
    for _, row in process_bandwidth.iterrows():
        curr_pid = row['pid']
        the_bandwidth = float(row['bandwidth'])
        if (the_bandwidth / total_bandwidth > BANDWIDTH):
            df.loc[curr_pid, 'Bandwidth Hog'] = True

    # Print 
    printing_df = df.copy()     # Copy for fancy printing
    try:    # apply getSize to scale stats
        printing_df['Download'] = printing_df['Download'].apply(getSize)
        printing_df['Upload'] = printing_df['Upload'].apply(getSize)
        printing_df['Download Speed'] = printing_df['Download Speed'].apply(getSize).apply(lambda s: f"{s}/s")  # Format to per-second 
        printing_df['Upload Speed'] = printing_df['Upload Speed'].apply(getSize).apply(lambda s: f"{s}/s") 
    except KeyError as e:
        pass    # DataFrame is empty 
    os.system('clear')
    print(printing_df.to_string())
    traffic_df = df     # Update global df

# Keep printing stats
def printStats():
    while program_running:
        time.sleep(1)
        print_pid_to_traffic()


# Main
if __name__ == '__main__':
    printing_thread = Thread(target=printStats, daemon=True)
        # daemon: thread terminates automatically when main program exits
    printing_thread.start()

    # Update the connections
    connections_thread = Thread(target=get_connections, daemon=True)
    connections_thread.start()

    # Start sniffing
    print('Started sniffing')
    try: 
        sniff(prn=process_packet, store=False)  # Don't store captured packets in memory
    except KeyboardInterrupt:
        program_running = False     # Whenever we exit sniff() function 
        printing_thread.join()
        connections_thread.join()   