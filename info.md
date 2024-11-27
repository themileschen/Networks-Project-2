## Running the program
`sudo python network_monitor_1.py <time in seconds>`\
`sudo python network_monitor_2.py`\
`sudo python network_monitor_3.py <threshold>` (or use default threshold of 0.5)

## Using iperf3 
Used to generate artificial traffic 
- Terminal 1: server
    - `iperf3 -s`
- Terminal 2: client
    - `iperf3 -c 127.0.0.1 -u -b 1G -t 30` for 1 GB/sec of UDP for 30 seconds

## Interfaces
- en0: Wi-Fi 
- lo0: loopback
- awdl0: Apple Wireless Direct Link 
- utun#: used by third-party networking applications

## Throttling with PF 
Throttling is a rate limiting mechanism to gradually reduce bandwidth usage, using a queue that acts like a "leaky bucket" algorithm. 
It does not immediately reduce usage below the specified threshold, but smooth out traffic over time.
- `pfctl` is a command-line tool used to configure Packet Filter (PF) firewall on macOS 
- `pfctl.txt` stores the `/etc/pf.conf` file            
    - 
 