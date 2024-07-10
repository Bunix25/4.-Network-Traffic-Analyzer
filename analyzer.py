import csv
from scapy.all import sniff, hexdump
from scapy.layers.inet import IP, TCP, UDP
from datetime import datetime

def packet_callback(packet, writer):
    if IP in packet:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        packet_info = packet.show(dump=True)  # Captures detailed packet information

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            writer.writerow([timestamp, ip_src, src_port, ip_dst, dst_port, 'TCP', packet_info])
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            writer.writerow([timestamp, ip_src, src_port, ip_dst, dst_port, 'UDP', packet_info])
        else:
            writer.writerow([timestamp, ip_src, '', ip_dst, '', 'IP', packet_info])

def main():
    interface = 'en0'  # Specify your interface here
    print(f"Capturing packets on interface: {interface}")
    
    with open('captured_packets.csv', 'w', newline='') as csvfile:
        fieldnames = ['Timestamp', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Protocol', 'Packet Info']
        writer = csv.writer(csvfile)
        writer.writerow(fieldnames)
        
        # Sniff packets on the specified interface
        sniff(prn=lambda x: packet_callback(x, writer), count=50, iface=interface)
        
if __name__ == "__main__":
    main()