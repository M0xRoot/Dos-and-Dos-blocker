# import the modules
import os
import sys
import time
import subprocess
from collections import defaultdict
from scapy.all import sniff, IP

THRESHOLD = 40  # decalte a var representing the maximum loud pack rate per second for an ip address
print(f"THRESHOLD: {THRESHOLD}")


# this functio receive the arument packet
def packet_callback(packet):
    src_ip = packet[IP].src  # extract the source ip address from the packet
    packet_count[src_ip] += 1  # inrement the packet count for the sorce ip address
    current_time = time.time()  # recording the time
    time_interval = current_time - start_time[0]  # calc the time interval

    # check if an or not DOS attack if it is a loop will execute either rating through the packet counts for each ip address
    if time_interval >= 1:
        for ip, count in packet_count.items():
            packet_rate = count / time_interval  # calc the packet rate
            # check if the packet rate didnt or not exceed the THRESHOLD and its from the blocked set or no
            if packet_rate > THRESHOLD and ip not in blocked_ips:
                print(f"Blocking IP: {ip}, packet_rate: {packet_rate}")
                subprocess.run(  # block the ip address using the iptables command
                    ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True
                )
                blocked_ips.add(ip)  # add the ip the address to the set of blocked ips

        packet_count.clear()
        start_time[0] = current_time


if __name__ == "__main__":
    if os.geteuid() != 0:  # get root privileges
        print("This script reqires root privileges.")
        sys.exit(1)
    # initialize the packet count dictionary
    # defaultdict is a specialized dictionary data structure (auto assin a default value when its first encounted)
    packet_count = defaultdict(int)
    start_time = [time.time()]
    blocked_ips = set()

    print("Monitoring network traffic...")
    # sniff packet and send them to the function packet_callback for analysis
    sniff(filter="ip", prn=packet_callback)
