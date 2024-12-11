'''
Basic network monitor using psutil and scapy with sending/receiving stats by process, including hogging flag

network_monitor_2.py
https://thepythoncode.com/article/make-a-network-usage-monitor-in-python


Extension with traffic blocking: use pfctl to manage the Packet Filter (PF) firewall on macOS to temporarily block hogging processes

ChatGPT
Perplexity AI
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
import subprocess   # for throttling

BANDWIDTH = 0.5     # If one process is using more than 50% of the total used bandwidth, it is "hogging"
BLOCK_THRESHOLD = 200 * 1024    # 200 KB/s 

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

# PIDs currently being blocked 
blocked_pids = set()

# Dictionary that maps PIDs to corresponding IP addresses 
pid_ips = {}

# Log file to track of blocking information
LOG_FILE = 'blocking_log.txt'

# Clear the output file of any existing contents from previous runs (using write mode)
with open(LOG_FILE, 'w') as log_file:
    pass

# Get program start time
START_TIME = datetime.now()

# Units of memory sizes
size = ['bytes', 'KB', 'MB', 'GB', 'TB']

# Function that returns bytes in a readable format
def getSize(bytes):
    for unit in size:
        if bytes < 1024:
            return f"{bytes:.1f}{unit}"
        bytes /= 1024

# To block processes that are hogging bandwidth
def block_bandwidth(ip, pid, bandwidth):

    # Print out current table for debugging 
    # result = subprocess.run("sudo pfctl -t ip_table -T show", shell=True, check=True, capture_output=True)
    # print(result.stdout.decode())
    
    with open(LOG_FILE, 'a') as log_file:   # append mode: add to existing file
        try:
            # Loads PF firewall rules
            subprocess.run(f"sudo pfctl -f /etc/pf_ip.conf", shell=True, check=True)
                # Subprocess: to run an external command
                # shell=True: command run through the shell
                # check=True: ensures exception is raised if applicable 

            # Add IP address to the blocking table 
            subprocess.run(f"sudo pfctl -t ip_table -T add {ip}", shell=True, check=True)
            
            time_update = datetime.now() - START_TIME
            msg = f"Blocked IP {ip}; Time = {time_update}; Current rate = {getSize(bandwidth)}\n"
            log_file.write(msg)

            blocked_pids.add(pid)     # add to set of currently blocked processes
        except Exception as e:
            error_msg = f"Failed to block IP {ip}: {e}\n"
            log_file.write(error_msg)

# Remove blocking for processes that are no longer hogging
def remove_block(ip, pid, bandwidth):

    # Print out current table for debugging 
    # result = subprocess.run("sudo pfctl -t ip_table -T show", shell=True, check=True, capture_output=True)
    # print(result.stdout.decode())
    
    with open(LOG_FILE, 'a') as log_file:
        try:
            # Delete IP address from the blocking table 
            subprocess.run(f"sudo pfctl -t ip_table -T delete {ip}", shell=True, check=True)
            
            # Remove process from the blocked set (if still exists in the set)
            blocked_pids.discard(pid)

            time_update = datetime.now() - START_TIME
            msg = f"Removed block for IP {ip}; Time = {time_update}; Current rate = {getSize(bandwidth)}\n"
            log_file.write(msg)

            try:
                subprocess.run("sudo pfctl -f /etc/pf.conf", shell=True, check=True)  # Reload default PF rules (no blocking)
            except:
                print("Failed to re-fresh rules after successful IP removal")
            
        except Exception as e:
            error_msg = f"Failed to remove blocking for IP {ip}: {e}\n"
            log_file.write(error_msg)
       
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
        df.sort_values('Download', inplace=True, ascending=False)
    except KeyError as e:
        pass    # DataFrame empty

    # Update bandwidth hogs and block necessary processes 
    for _, row in process_bandwidth.iterrows():
        curr_pid = row['pid']
        the_bandwidth = float(row['bandwidth'])
        if (the_bandwidth / total_bandwidth > BANDWIDTH):
            df.loc[curr_pid, 'Bandwidth Hog'] = True
            if ((the_bandwidth > (BLOCK_THRESHOLD)) & (curr_pid not in blocked_pids)):  # Only block if it is a) hogging, and b) exceeds the block threshold, and c) the process is not already being blocked
                ips = get_ip(curr_pid)  # Get associated IP addresses 
                ips_to_add = set()
                if ips:
                    for ip in ips:
                        ips_to_add.add(ip)  # Add to list of IPs to block 
                        block_bandwidth(ip, curr_pid, the_bandwidth)    # Block it 
                    add_ips(curr_pid, ips_to_add)   # Store newly blocked IPs with the associated PID for future reference when unblocking
        elif (curr_pid in blocked_pids):   # Currently blocked, but no longer hogging
            iterate_ips(curr_pid, the_bandwidth)    # Release the IPs currently blocked for this process
            remove_pid(curr_pid)    # Remove the PID from the set of blocked PIDs 

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

# Restore default PF configuration file on computer (/etc/pf.conf)
def restore_defaults():
    try:
        subprocess.run("sudo pfctl -f /etc/pf.conf", shell=True, check=True)
        print("Default PF rules restored.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to restore defaults: {e}")

# Return list of IPs for a PID 
def get_ip(pid):
    try:
        # Get the process by PID
        process = psutil.Process(pid)
        
        # Get the network connections for the process
        connections = process.net_connections(kind='inet')  # 'inet' for IPv4 and IPv6 connections
        
        # Loop through connections 
        ip_addresses = set()
        for conn in connections:
            # conn.laddr is the local address, conn.raddr is the remote address
            if conn.raddr:
                ip_addresses.add(conn.raddr.ip)     # Add remote IP to set
        
        if ip_addresses:
            return ip_addresses
        else:
            return "No network connections for this PID."
    except psutil.NoSuchProcess:
        return f"No process found with PID {pid}."
    except psutil.AccessDenied:
        return f"Access denied to process with PID {pid}."
    except Exception as e:
        return str(e)

# Clear the IP table from any previous runs/blocking
def clear_ip_table(table_name='ip_table'):
    try:
        subprocess.run(f"sudo pfctl -t {table_name} -T flush", shell=True, check=True)
        print(f"Table '{table_name}' cleared successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to clear table '{table_name}': {e}")

# Add IPs that are associated with a PID 
def add_ips(pid, ips):
    if pid in pid_ips:
        pid_ips[pid].extend(ips)
    else:
        pid_ips[pid] = ips

# Remove PID (and associated IPs) from the blocked list 
def remove_pid(pid):
    if pid in pid_ips:
        del pid_ips[pid]

# Remove blocking for IPs in specified PID 
def iterate_ips(pid, the_bandwidth):
    if pid in pid_ips:
        for ip in pid_ips[pid]:
            remove_block(ip, pid, the_bandwidth)
    else:
        print(f"No IPs found for PID {pid}")


# Main
if __name__ == '__main__':
    clear_ip_table()    # Ensure no IPs are blocked to start

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
    finally:
        # Restore default PF rules on computer upon termination of program
        restore_defaults()