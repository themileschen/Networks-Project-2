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

# Status of program
program_running = True 

# Dictionary to store traffic by protocol
traffic_by_protocol = defaultdict(lambda: [0, 0])   # [Upload, Download]

# Get the MAC addresses of all network interfaces on the machine
ifaces = conf.ifaces
all_macs = {iface.mac for iface in ifaces.values()}
    # ifaces represents interface names (e.g. eth0) that are automatically initialized by Scapy 

def get_protocol_name(packet):
    if packet.haslayer(TCP):
        if packet[TCP].dport in [80] or packet[TCP].sport in [80]:
            return "HTTP"
        elif packet[TCP].dport in [443] or packet[TCP].sport in [443]:
            return "HTTPS"
        elif packet[TCP].dport in [20, 21] or packet[TCP].sport in [20, 21]:
            return "FTP"
        elif packet[TCP].dport in [25] or packet[TCP].sport in [25]:
            return "SMTP"
    elif packet.haslayer(UDP):
        if packet[UDP].dport in [53] or packet[UDP].sport in [53]:
            return "DNS"
    return "Other"
        
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

# Iterate over process dictionary 
# Use traffic_df to get previous total usage and calculate current speed
# Append the process to processes list and convert to DataFrame for printing
def printStats():
    while program_running:
        time.sleep(1)
        os.system('clear')
        print(f"{'Protocol':<10}{'Upload':>15}{'Download':>15}")
        print("=" * 40)
        
        for protocol, (upload, download) in traffic_by_protocol.items():
            print(f"{protocol:<10}{getSize(upload):>15}{getSize(download):>15}")

    # global traffic_df
    # processes = []  # Initialize list of processes
    # total_bandwidth = 0     # Total current bandwidth consumed 
    # process_bandwidth = pd.DataFrame(columns=['pid', 'bandwidth'])  # Current bandwidth consumed 
    # for pid, traffic in list(pid_to_traffic.items()):   # list: create static items to iterate (prevent concurrent thread Runtime error)
    #     # pid is integer; traffic is a list of total upload and download size
    #     try:
    #         p = psutil.Process(pid)     # Get process object 
    #     except psutil.NoSuchProcess:    # Process not found
    #         continue
    #     name = p.name()     # Get process name
    #     # Get time the packet was spawned
    #     try:
    #         create_time = datetime.fromtimestamp(p.create_time())
    #     except OSError:
    #         # System processes, using boot time instead
    #         create_time = datetime.fromtimestamp(psutil.boot_time())
    #     # Construct dictionary to store process info
    #     process = {
    #         'pid': pid, 'name': name, 'create_time': create_time, 
    #         'Upload': traffic[0], 'Download': traffic[1], 'Bandwidth Hog': False
    #     }
    #     try:
    #         # Calculate upload and download speeds (subtract old stats)
    #         process['Upload Speed'] = traffic[0] - traffic_df.at[pid, 'Upload']            
    #         process['Download Speed'] = traffic[1] - traffic_df.at[pid, 'Download']
    #     except (KeyError, AttributeError):
    #         # If first time running function, the speed is just the current traffic
    #         process['Upload Speed'] = traffic[0]
    #         process['Download Speed'] = traffic[1]
    #     # Update bandwidth metrics 
    #     current_bandwidth = process['Upload Speed'] + process['Download Speed']
    #     total_bandwidth = total_bandwidth + current_bandwidth
    #     process_bandwidth.loc[len(process_bandwidth)] = [pid, current_bandwidth]
    #     processes.append(process)   # Append to list 
    # # Set up DataFrame
    # df = pd.DataFrame(processes)  
    # try:
    #     df = df.set_index('pid')
    #     df.sort_values('Download', inplace=True, ascending=False)
    # except KeyError as e:
    #     pass    # DataFrame empty

    # # Update bandwidth hogs 
    # for _, row in process_bandwidth.iterrows():
    #     curr_pid = row['pid']
    #     the_bandwidth = float(row['bandwidth'])
    #     if (the_bandwidth / total_bandwidth > BANDWIDTH):
    #         df.loc[curr_pid, 'Bandwidth Hog'] = True

    # # Print 
    # printing_df = df.copy()     # Copy for fancy printing
    # try:    # apply getSize to scale stats
    #     printing_df['Download'] = printing_df['Download'].apply(getSize)
    #     printing_df['Upload'] = printing_df['Upload'].apply(getSize)
    #     printing_df['Download Speed'] = printing_df['Download Speed'].apply(getSize).apply(lambda s: f"{s}/s")  # Format to per-second 
    #     printing_df['Upload Speed'] = printing_df['Upload Speed'].apply(getSize).apply(lambda s: f"{s}/s") 
    # except KeyError as e:
    #     pass    # DataFrame is empty 
    # os.system('clear')zz
    # print(printing_df.to_string())
    # traffic_df = df     # Update global df


# Main
if __name__ == '__main__':
    printing_thread = Thread(target=printStats, daemon=True)
        # daemon: thread terminates automatically when main program exits
    printing_thread.start()

    # # Start sniffing
    # print('Started sniffing')
    # try: 
    #     sniff_thread = Thread(target=lambda: sniff(prn=process_packet, store=False), daemon=True)
    #         # Don't store captured packets in memory
    #     sniff_thread.start()
    # except KeyboardInterrupt:
    #     program_running = False     # Whenever we exit sniff() function 
    #     printing_thread.join()
    #     sniff_thread.join()   

    # Start sniffing
    print('Started sniffing')
    try: 
        sniff(prn=process_packet, store=False)  # Don't store captured packets in memory
    except KeyboardInterrupt:
        program_running = False     # Whenever we exit sniff() function 
        printing_thread.join()
