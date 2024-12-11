## Running the programs
`sudo python network_monitor_1.py <time in seconds>`\
`sudo python network_monitor_2.py`\
`sudo python network_monitor_3.py <threshold>` (or use default threshold of 0.5)\
`sudo python ip_blocking.py`\
`sudo python network_montior_4.py`\
Use keyboard interrupt to terminate program (except `network_monitor_1.py`)

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

## Blocking with PF 
- `pfctl` is a command-line tool used to configure Packet Filter (PF) firewall on macOS 
- `ip_blocking_conf.txt` stores the contents of the `/etc/pf_ip.conf` file 
- Results are displayed in `blocking_log.txt`
- **Before running**, ensure PF is enabled (`sudo pfctl -e`) 
