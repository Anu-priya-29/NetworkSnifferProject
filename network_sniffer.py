from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import datetime

# Open the log file in append mode
def log_to_file(info):
    with open("packet_logs.txt", "a") as log_file:
        log_file.write(f"{datetime.datetime.now()} - {info}\n")

def process_packet(packet):
    print("\n--- New Packet Captured ---")

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        info = f"Source: {src_ip}, Destination: {dst_ip}, Protocol: {proto}"
        print(info)

        if packet.haslayer(TCP):
            ports = f"TCP Port: {packet[TCP].sport} -> {packet[TCP].dport}"
            print(ports)
            info += f", {ports}"
        elif packet.haslayer(UDP):
            ports = f"UDP Port: {packet[UDP].sport} -> {packet[UDP].dport}"
            print(ports)
            info += f", {ports}"
        elif packet.haslayer(ICMP):
            print("ICMP Packet")
            info += ", ICMP Packet"

        if packet.haslayer(Raw):
            payload = packet[Raw].load
            data = f"Payload: {payload[:50]}"
            print(data)
            info += f", {data}"

        # Log the info
        log_to_file(info)

    else:
        print("Non-IP Packet Detected")

print("Starting packet capture... (Press Ctrl+C to stop)")
sniff(filter="ip", prn=process_packet, store=False)
