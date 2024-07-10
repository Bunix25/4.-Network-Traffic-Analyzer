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

def main():
    packets = read_packets('captured_packets.csv')
    detect_anomalies(packets)

if __name__ == "__main__":
    main()