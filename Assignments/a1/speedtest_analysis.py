from scapy.all import rdpcap, IP, TCP
import numpy as np
import argparse
import matplotlib.pyplot as plt
from collections import defaultdict
import sys

def parse_pcap(filename):
    return rdpcap(filename)


def plot_throughput(packets):
    download_series = defaultdict(int)
    upload_series = defaultdict(int)
    ip_packet_count = 0
    start_time = float(packets[0].time)
    dst_ip = packets[0].dst
    src_ip = packets[0].src
    for pkt in packets:
        if pkt.haslayer('IP') and pkt.haslayer('TCP'):
            if pkt['TCP'].dport == 80 or pkt['TCP'].dport == 443 or pkt['TCP'].sport == 80 or pkt['TCP'].sport == 443:
                ip_packet_count += 1
                timestamp = float(pkt.time) - start_time
                size = len(pkt)
                ip_layer = pkt['IP']
                if pkt['TCP'].sport == 80 or pkt['TCP'].sport == 443:
                    download_series[timestamp] += size
                elif pkt['TCP'].dport == 80 or pkt['TCP'].dport == 443:
                    upload_series[timestamp] += size

    sorted_times = sorted(set(download_series.keys()).union(upload_series.keys()))
    download_throughput = [(download_series[t] * 8 / 1e6) if t in download_series else 0 for t in sorted_times]
    upload_throughput = [(upload_series[t] * 8 / 1e6) if t in upload_series else 0 for t in sorted_times]
    plt.plot(sorted_times, download_throughput, marker='o', linestyle='-', label='Download')
    plt.plot(sorted_times, upload_throughput, marker='o', linestyle='-', label='Upload')
    plt.xlabel('Time (s)')
    plt.ylabel('Throughput (Mbps)')
    plt.title('Time-Series of Download and Upload Throughput (NDT7 Packets)')
    plt.legend()
    plt.show()





def calculate_throughput(packets):
    download_series = defaultdict(int)
    upload_series = defaultdict(int)
    ip_packet_count = 0
    start_time = float(packets[0].time)
    end_time = 0
    for pkt in packets:
        if pkt.haslayer('IP') and pkt.haslayer('TCP'):
            if pkt['TCP'].dport == 80 or pkt['TCP'].dport == 443 or pkt['TCP'].sport == 80 or pkt['TCP'].sport == 443:
                ip_packet_count += 1
                timestamp = float(pkt.time)
                end_time = max(end_time, timestamp)
                size = len(pkt)
                ip_layer = pkt['IP']
                if pkt['TCP'].sport == 80 or pkt['TCP'].sport == 443:
                    download_series[timestamp] += size
                elif pkt['TCP'].dport == 80 or pkt['TCP'].dport == 443:
                    upload_series[timestamp] += size

    total_time = end_time - start_time
    download_speed = sum(download_series.values()) * 8 / 1e6 / total_time
    upload_speed = sum(upload_series.values()) * 8 / 1e6 / total_time
    return download_speed,upload_speed

def calculate_percentage(packets):
    download_packet = 0
    upload_packet = 0
    ip_packet_count = 0
    start_time = float(packets[0].time)
    total_pkt = 0
    d_pkt = 0
    u_pkt = 0
    end_time = 0
    for pkt in packets:
        ip_packet_count += len(pkt)
        total_pkt += 1
        end_time = max(end_time, float(pkt.time))
        if pkt.haslayer('IP') and pkt.haslayer('TCP'):
            if pkt['TCP'].dport == 80 or pkt['TCP'].dport == 443 or pkt['TCP'].sport == 80 or pkt['TCP'].sport == 443:
                timestamp = float(pkt.time) - start_time
                ip_layer = pkt['IP']
                if pkt['TCP'].sport == 80 or pkt['TCP'].sport == 443:
                    download_packet += len(pkt)
                    d_pkt += 1
                elif pkt['TCP'].dport == 80 or pkt['TCP'].dport == 443:
                    upload_packet += len(pkt)
                    u_pkt += 1

    download_percentage = (download_packet / ip_packet_count) * 100
    upload_percentage = (upload_packet / ip_packet_count) * 100
    time = end_time - start_time
    print("Upload Percentage: ",upload_percentage)
    print("Download Percentage: ",download_percentage)
    print("Total Mb: " , ip_packet_count / 1e6)
    print("Upload Mb: ", upload_packet / 1e6)
    print("Download Mb:", download_packet / 1e6)
    print("Total Packets: ", total_pkt)
    print("Upload Packets: ", u_pkt)
    print("Download Packets: ", d_pkt)


def main():
    parser = argparse.ArgumentParser(description="Analyze NDT7 speed test PCAP files")
    parser.add_argument("pcap", help="Input PCAP file")
    parser.add_argument("--plot", action="store_true", help="Plot time-series of throughput")
    parser.add_argument("--throughput", action="store_true", help="Calculate average download and upload speeds")
    parser.add_argument("--percentage", action="store_true", help="Calculate percentage of traffic with NDT7 packets")
    args = parser.parse_args()

    packets = parse_pcap(args.pcap)

    if args.plot:
        plot_throughput(packets)

    if args.throughput:
        download_speed, upload_speed = calculate_throughput(packets)
        print(f"{download_speed:.2f},{upload_speed:.2f}")

    if args.percentage:
        calculate_percentage(packets)

if __name__ == "__main__":
    main()
