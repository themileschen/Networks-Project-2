'''
Initial throttling code (archive)
'''

# To slow-down processes that are hogging bandwidth
def throttle_bandwidth(pid, rate='200Kbit/s'):
    with open(LOG_FILE, 'w') as log_file:   # write mode: any existing file contents are overwritten
        # Identify the IP/port for the process (one process can have many connections)
        try:
            process_connections = psutil.Process(pid).net_connections()
            pipe_id = pid   # Unique pipe ID for each process

            for conn in process_connections:
                target_ip = conn.raddr.ip
                target_port = conn.raddr.port 

                # Create and apply pipe for the connection
                subprocess.run(f"sudo pfctl -t pid_table -T add {pipe_id}", shell=True, check=True)
                    # shell=True for shell-specific behavior (pipes); check=True for error handling
                subprocess.run(f"sudo pfctl -t pipe {pipe_id} config bw {rate}", shell=True, check=True)
                
                # print(f"Throttled PID {pid} to {rate}")
                msg = f"Throttled PID {pid} to {rate} for IP {target_ip}:{target_port}\n"
                log_file.write(msg)

            throttled_pids.add(pid)     # add to set of currently throttled processes
        except Exception as e:
            # print(f"Failed to throttle PID {pid}: {e}")
            error_msg = f"Failed to throttle PID {pid}: {e}\n"
            log_file.write(error_msg)

# write throttling message to output file (along with current speed)


# Remove throttling for processes that are no longer hogging
def remove_throttle(pid):
    with open(LOG_FILE, 'w') as log_file:
        try:
            subprocess.run(f"sudo pfctl -t pid_table -T delete {pid}", shell=True, check=True)

            # Remove from throttled set 
            throttled_pids.remove(pid)

            msg = f"Removed throttle for PID {pid}\n"
            log_file.write(msg)
        except Exception as e:
            # print(f"Failed to remove throttle for PID {pid}: {e}")
            error_msg = f"Failed to remove throttle for PID {pid}: {e}\n"
            log_file.write(error_msg)