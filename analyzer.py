import csv
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from scapy.config import conf

def packet_callback(packet, writer):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            writer.writerow([ip_src, src_port, ip_dst, dst_port, 'TCP'])
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            writer.writerow([ip_src, src_port, ip_dst, dst_port, 'UDP'])
        else:
            writer.writerow([ip_src, '', ip_dst, '', 'IP'])

def main():
    interface = 'en0'  # Specify your interface here
    print(f"Capturing packets on interface: {interface}")
    
    with open('captured_packets.csv', 'w', newline='') as csvfile:
        fieldnames = ['Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Protocol']
        writer = csv.writer(csvfile)
        writer.writerow(fieldnames)
        
        # Sniff packets on the specified interface
        sniff(prn=lambda x: packet_callback(x, writer), count=50, iface=interface)
        
if __name__ == "__main__":
    main()