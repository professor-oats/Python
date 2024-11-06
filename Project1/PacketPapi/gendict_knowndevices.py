## This script is to generate a list of known/trusted devices on the network
## Make sure to run this only when you have checked the network not containing any unwanted hosts

from scapy.layers.l2 import ARP, Ether, srp
import json


def arp_scan(in_target_ip_range):
  # Create an ARP request packet
  arp = ARP(pdst=in_target_ip_range)
  # Create an Ethernet frame
  ether = Ether(dst="ff:ff:ff:ff:ff:ff")  ## Use broadcast
  # Combine ARP and Ethernet frame
  packet = ether / arp

  # Send the packet and receive the response
  result = srp(packet, timeout=3, verbose=False)[0]

  # Dictionary to store known devices
  known_devices = {}

  # Process the responses
  for sent, received in result:
    # Store the IP and MAC address in the dictionary
    known_devices[received.psrc] = received.hwsrc

  return known_devices

def main():
  # Set the target IP range for the scan
  target_ip_range = "192.168.10.0/24"
  devices = arp_scan(target_ip_range)

# Print the known devices in the specified format
  print("Known devices:")
  print("known_devices = {")
  for ip, mac in devices.items():
    print(f"    '{ip}': '{mac}',")
  print("}")

# Save the results to a JSON file
  with open('known_devices.json', 'w') as json_file:
    json.dump(devices, json_file, indent=2)

  print("Device information has been saved to known_devices.json.")

if __name__ == "__main__":
  main()

