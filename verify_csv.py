import csv

def read_captured_packets(file_path):
    with open(file_path, 'r') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            print(row)

if __name__ == "__main__":
    read_captured_packets('captured_packets.csv')