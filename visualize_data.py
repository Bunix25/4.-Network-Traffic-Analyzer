import csv
from collections import Counter
import matplotlib.pyplot as plt

def read_packets(file_path):
    packets = []
    with open(file_path, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            packets.append(row)
    return packets

def visualize_source_ip_counts(packets):
    ip_counts = Counter(packet['Source IP'] for packet in packets)
    labels, values = zip(*ip_counts.items())

    plt.figure(figsize=(10, 6))
    plt.bar(labels, values, color='skyblue')
    plt.xlabel('Source IP')
    plt.ylabel('Number of Packets')
    plt.title('Source IP Counts')
    plt.xticks(rotation=45)
    plt.show()

def main():
    packets = read_packets('captured_packets.csv')
    visualize_source_ip_counts(packets)

if __name__ == "__main__":
    main()