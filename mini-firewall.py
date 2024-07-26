import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP

THRESHOLD = 40
print(f"THRESHOLD: {THRESHOLD}")

def read_ipFile(filename):
    with open(filename, "r") as file:
        ips = [line.strip() for line in file]
        return set(ips)
    
def is_nimda_worm(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        payload = packet[TCP].payload
        return "GET /scripts/root.exe" in str(payload)
    return False

def logEvent(msg):
    logFolder = "logs"
    os.makedirs(logFolder, exist_ok=True)
    timestamp= time.strftime("%Y-$m-%d_%H-%M-%S", time.localtime())
    logFile = os.path.join(logFolder, f"log_{timestamp}.txt")

    with open(logFile, "a") as file:
        file.write(f"{msg}\n")


def packet_callback(packet):
    src_ip = packet[IP].src

    if src_ip in whitelist_ips:
        return
    if src_ip in blacklist_ips:
        os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
        logEvent(f"blocking blacklisted IP: {src_ip}")
        return
    
    if is_nimda_worm(packet):
        print(f"blocking nimda source ip: {src_ip}")
        os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
        logEvent(f"blocking nimda source ip: {src_ip}")
        return
    packet_count[src_ip] += 1 


    current_time = time.time()
    time_interval = current_time - startTime[0]

    if time_interval >= 1:
        for ip, count in packet_count.items():
            packet_rate = count / time_interval


            if packet_rate > THRESHOLD and ip not in blocked_ips:
                print(f"blocking ip: {ip}, packet rate: {packet_rate}")
                os.system(f"iptables -A INPUT -s {ip} -j DROP")
                logEvent(f"blocking ip: {ip}, packet rate: {packet_rate}")
                blocked_ips.add(ip)

        packet_count.clear()
        startTime[0] = current_time


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This script requires root privileges")
        sys.exit(1)

        whitelist_ips = read_ipFile("whitelist.txt")
        blacklist_ips = read_ipFile("blacklist.txt")

    packet_count = defaultdict(int)
    startTime = [time.time()]
    blocked_ips = set()

    print("monitoring network traffic...")
    sniff(filter="ip", prn=packet_callback)