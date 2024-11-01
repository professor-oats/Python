from scapy.layers.l2 import ARP
from scapy.layers.inet import IP
from scapy.all import sniff
from collections import defaultdict
import logging
import time

logging.basicConfig(filename='arp_monitor.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Dictionary to track IP to MAC mappings
arp_table = defaultdict(set)
arp_timestamps = defaultdict(list)

# Dictionary to track IP-to-TTL mappings
ttl_mapping = {}

# Construction of known_devices dict for fine grain checking
known_devices = {
    '192.168.10.1': 'ff:ff:ff:ff:ff:ff',  # Example known gateway MAC
    # Add more known devices here
}

ARP_RESPONSE_THRESHOLD = 4  # Change to wanted threshold
TIME_WINDOW = 10  # Change time window in seconds to check the threshold

def detect_suspicious_arp(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP response
        src_ip = packet[ARP].psrc
        src_mac = packet[ARP].hwsrc

        # Print ARP response
        print(f"ARP response from {src_ip} - MAC {src_mac}")

        # Log the ARP response
        logging.info(f"ARP response from {src_ip} - MAC {src_mac}")

        # Check for duplicate MAC addresses for the same IP
        arp_table[src_ip].add(src_mac)
        if len(arp_table[src_ip]) > 1:
          alert_message = f"[ALERT] Duplicate MAC addresses for IP {src_ip}: {arp_table[src_ip]}"
          print(alert_message)
          logging.warning(alert_message)

        # Use for fine grain checking for unusual IP-MAC mappings
        #if src_ip in known_devices and known_devices[src_ip] != src_mac:
         # alert_message = f"[ALERT] Suspicious MAC for known IP {src_ip}: {src_mac}"
         # print(alert_message)
         # logging.warning(alert_message)

        # Track timestamps for frequency analysis
        current_time = time.time()
        arp_timestamps[src_ip].append(current_time)

        # Analyze frequency of ARP responses over the last 10 seconds
        analyze_frequency(src_ip)

    if packet.haslayer(IP):
      src_ip = packet[IP].src
      ttl = packet[IP].ttl

      # Check if the IP has been seen with a different TTL
      if src_ip in ttl_mapping and ttl_mapping[src_ip] != ttl:
        alert_message = f"[ALERT] TTL anomaly detected for {src_ip}. Previous TTL: {ttl_mapping[src_ip]}, Current TTL: {ttl}"
        print(alert_message)
        logging.warning(alert_message)
      else:
        ttl_mapping[src_ip] = ttl


def analyze_frequency(src_ip):  # Make sure to check the network onbeforehand to set appropriate thresholds
  # Define the time window for frequency analysis (in seconds)

  cutoff_time = time.time() - TIME_WINDOW

  # Filter timestamps to only include those within the time window
  recent_timestamps = [t for t in arp_timestamps[src_ip] if t > cutoff_time]

  # Count the number of ARP responses in the recent timestamps
  response_count = len(recent_timestamps)

  # If the response count exceeds a threshold, log an alert
  if response_count > ARP_RESPONSE_THRESHOLD:  # Example threshold
    alert_message = f"[ALERT] High frequency of ARP responses from {src_ip}: {response_count} responses in the last {TIME_WINDOW} seconds"
    print(alert_message)
    logging.warning(alert_message)

def main():
  print("Monitoring for suspicious ARP activities...")
  sniff(filter="arp", prn=detect_suspicious_arp)

if __name__ == "__main__":
  main()