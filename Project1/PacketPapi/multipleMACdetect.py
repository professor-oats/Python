from scapy.layers.l2 import ARP
from scapy.all import sniff
from collections import defaultdict

# Dictionary to track IP-to-MAC mappings
arp_table = defaultdict(set)


def detect_duplicate_arp(packet):
  if packet.haslayer(ARP) and packet[ARP].op == 1:  # ARP request
    # Extract the IP and MAC addresses
    src_ip = packet[ARP].psrc
    src_mac = packet[ARP].hwsrc

    # Update the ARP table
    arp_table[src_ip].add(src_mac)

    # Check if the current IP has more than one MAC
    if len(arp_table[src_ip]) > 1:
      print(f"[ALERT] Duplicate IP detected: {src_ip} has MACs {arp_table[src_ip]}")

def main():
  print("Monitoring ARP packets for duplicates...")
  sniff(filter="arp", prn=detect_duplicate_arp)

if __name__ == "__main__":
  main()