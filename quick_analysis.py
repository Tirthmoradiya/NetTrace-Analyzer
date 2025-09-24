#!/usr/bin/env python3
"""
Quick analysis of PCAP file using Scapy directly
"""

import sys
from collections import Counter, defaultdict
from scapy.all import rdpcap, IP, TCP, UDP, DNS, Raw, ICMP
import json

def analyze_pcap(pcap_file):
    print(f"Analyzing {pcap_file}...")
    
    try:
        packets = rdpcap(pcap_file)
        print(f"Total packets loaded: {len(packets)}")
        
        # Basic statistics
        protocol_stats = Counter()
        ip_pairs = Counter()
        port_stats = Counter()
        dns_queries = []
        
        tcp_packets = 0
        udp_packets = 0
        icmp_packets = 0
        dns_packets = 0
        http_packets = 0
        
        for pkt in packets:
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                ip_pairs[(src_ip, dst_ip)] += 1
                
                if TCP in pkt:
                    tcp_packets += 1
                    protocol_stats['TCP'] += 1
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport
                    port_stats[dst_port] += 1
                    
                    # Check for HTTP
                    if pkt[TCP].dport == 80 or pkt[TCP].sport == 80:
                        http_packets += 1
                        protocol_stats['HTTP'] += 1
                        
                elif UDP in pkt:
                    udp_packets += 1
                    protocol_stats['UDP'] += 1
                    src_port = pkt[UDP].sport
                    dst_port = pkt[UDP].dport
                    port_stats[dst_port] += 1
                    
                    # Check for DNS
                    if DNS in pkt:
                        dns_packets += 1
                        protocol_stats['DNS'] += 1
                        if pkt[DNS].qr == 0 and pkt[DNS].qd:  # Query
                            query = pkt[DNS].qd.qname.decode('utf-8').rstrip('.')
                            dns_queries.append(query)
                            
                elif ICMP in pkt:
                    icmp_packets += 1
                    protocol_stats['ICMP'] += 1
        
        # Print results
        print("\n=== PACKET ANALYSIS RESULTS ===")
        print(f"Total packets: {len(packets)}")
        print(f"TCP packets: {tcp_packets}")
        print(f"UDP packets: {udp_packets}")
        print(f"ICMP packets: {icmp_packets}")
        print(f"DNS packets: {dns_packets}")
        print(f"HTTP packets: {http_packets}")
        
        print(f"\n=== PROTOCOL DISTRIBUTION ===")
        for protocol, count in protocol_stats.most_common():
            print(f"{protocol}: {count} packets")
            
        print(f"\n=== TOP 10 DESTINATION PORTS ===")
        for port, count in port_stats.most_common(10):
            print(f"Port {port}: {count} connections")
            
        print(f"\n=== TOP 10 IP COMMUNICATIONS ===")
        for (src, dst), count in ip_pairs.most_common(10):
            print(f"{src} -> {dst}: {count} packets")
            
        if dns_queries:
            print(f"\n=== DNS QUERIES (first 10) ===")
            unique_queries = list(set(dns_queries))[:10]
            for query in unique_queries:
                print(f"  {query}")
                
        # Look for potential threats
        print(f"\n=== POTENTIAL SECURITY INDICATORS ===")
        
        # Check for port scanning (many different dest ports from same source)
        src_to_ports = defaultdict(set)
        for pkt in packets:
            if IP in pkt and TCP in pkt:
                src_ip = pkt[IP].src
                dst_port = pkt[TCP].dport
                src_to_ports[src_ip].add(dst_port)
        
        for src_ip, ports in src_to_ports.items():
            if len(ports) > 10:  # Potential port scan
                print(f"⚠️  Potential port scan from {src_ip}: {len(ports)} different ports")
                
        # Check for suspicious DNS queries (very long domain names)
        for query in dns_queries:
            if len(query) > 50:
                print(f"⚠️  Suspicious long DNS query: {query[:50]}...")
                
        # Check for high traffic IPs
        ip_traffic = Counter()
        for (src, dst), count in ip_pairs.items():
            ip_traffic[src] += count
            ip_traffic[dst] += count
            
        print(f"\n=== HIGH TRAFFIC IPs ===")
        for ip, count in ip_traffic.most_common(5):
            print(f"{ip}: {count} total packets")

    except Exception as e:
        print(f"Error analyzing PCAP: {e}")
        return False
    
    return True

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python quick_analysis.py <pcap_file>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    analyze_pcap(pcap_file)