import csv
from collections import Counter

def read_packets(file_path):
    packets = []
    with open(file_path, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            packets.append(row)
    return packets

def detect_anomalies(packets):
    # Detect unusual traffic from a single source IP
    ip_counts = Counter(packet['Source IP'] for packet in packets)
    threshold_ip = 5  # Lower the threshold for testing
    print("\nSource IPs with unusually high traffic:")
    for ip, count in ip_counts.items():
        if count > threshold_ip:
            print(f"{ip}: {count} packets")

    # Detect traffic to unusual ports
    port_counts = Counter(packet['Destination Port'] for packet in packets if packet['Destination Port'])
    threshold_port = 2  # Lower the threshold for testing
    print("\nUnusual Destination Ports with high traffic:")
    for port, count in port_counts.items():
        if count > threshold_port and int(port) > 1024:
            print(f"Port: {port}, Count: {count}")

    # Print more information for insight
    print("\nAll Source IP Counts:")
    for ip, count in ip_counts.items():
        print(f"{ip}: {count} packets")

    print("\nAll Destination Port Counts:")
    for port, count in port_counts.items():
        print(f"Port: {port}, Count: {count}")

def get_detailed_info(packets, timestamp, src_ip, src_port, dst_ip, dst_port, protocol):
    found = False
    for packet in packets:
        print(f"Checking packet: {packet}")  # Debug: Print each packet being checked
        if (packet['Timestamp'] == timestamp and packet['Source IP'] == src_ip and
            packet['Source Port'] == src_port and packet['Destination IP'] == dst_ip and
            packet['Destination Port'] == dst_port and packet['Protocol'] == protocol):
            found = True
            print(f"\nDetailed Packet Information for {timestamp}, {src_ip}, {src_port}, {dst_ip}, {dst_port}, {protocol}:")
            print(packet['Packet Info'])
            break
    if not found:
        print("No matching packet found.")

def main():
    packets = read_packets('captured_packets.csv')
    print(f"Total packets read: {len(packets)}")  # Debug: Print the total number of packets read
    detect_anomalies(packets)
    # Replace with the specific data point you want to investigate
    get_detailed_info(packets, '2024-07-10 13:11:13', '10.0.0.190', '62373', '20.189.173.15', '443', 'TCP')

if __name__ == "__main__":
    main()