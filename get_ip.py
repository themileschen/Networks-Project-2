'''
to practice getting IP addresses from PIDs
'''

import psutil
import os 

def get_ip(pid):
    try:
        # Get the process by PID
        process = psutil.Process(pid)
        
        # Get the network connections for the process
        connections = process.net_connections(kind='inet')  # 'inet' for IPv4 and IPv6 connections
        
        # Loop through connections and print the IP addresses
        ip_addresses = set()
        for conn in connections:
            # conn.laddr is the local address, conn.raddr is the remote address
            if conn.raddr:
                ip_addresses.add(conn.raddr.ip)  # Add remote IP to set
        
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

if __name__ == '__main__':
    pid = os.getpid()
    pid = 47925
    print(f"Process ID: {pid}")
    result = get_ip(pid)
    for ip in result:
        print(ip)
   