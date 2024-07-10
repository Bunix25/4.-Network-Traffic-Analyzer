import csv
from collections import Counter

def read_packets(file_path):
    packets = []
    with open(file_path, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            packets.append(row)
    return packets

def analyze_packets(packets):
    protocols = Counter(packet['Protocol'] for packet in packets)
    print("Protocol Distribution:")
    for protocol, count in protocols.items():
        print(f"{protocol}: {count} packets")

    top_sources = Counter(packet['Source IP'] for packet in packets).most_common(5)
    print("\nTop 5 Source IPs:")
    for ip, count in top_sources:
        print(f"{ip}: {count} packets")

def main():
    packets = read_packets('captured_packets.csv')
    analyze_packets(packets)

if __name__ == "__main__":
    main()