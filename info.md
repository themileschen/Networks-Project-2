## Running the program
`sudo python network_monitor_1.py`

## Using iperf3 
Used to generate artificial traffic 
- Terminal 1: server
    - `iperf3 -s`
- Terminal 2: client
    - `iperf3 -c 127.0.0.1 -u -b 1G -t 30` for 1 GB/sec of UDP for 30 seconds
