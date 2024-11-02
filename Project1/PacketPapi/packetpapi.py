from . import multipleMACdetect
from . import arppoison_monitor
from . import mitm_arp
from scapy.layers.l2 import getmacbyip, get_if_hwaddr
from scapy.all import conf
import multiprocessing
import ipaddress

BANNER = """
\033[34m#######################################
###  \033[0m-  Welcome to \033[95mpacketpapi\033[0m  - \033[34m   ###
###  \033[0myour personal packet commander\033[34m ###
#######################################\033[0m
"""
CATEGORIES = """\033[1m\033[95mOFFENSIVE SCRIPTS\033[0m
[\033[97mC\033[0m]ustom MitM ARP - Construct a MitM between two network devices

\033[1m\033[95mDEFENSIVE SCRIPTS\033[0m
[\033[97mA\033[0m]RP-poison monitor - MitM mitigate
[\033[97mM\033[0m]ultiple MAC detect - MitM mitigate

\033[1m\033[95mMENU COMMANDS\033[0m
[\033[97mB\033[0m]ack
"""

# Just a check to see if the IP is correctly formatted
def is_valid_ip(target):
  try:
    ipaddress.ip_address(target)
    return True
  except ValueError:
    return False

def main():
  print(BANNER)

  while True:
    print(CATEGORIES)
    userchoice = input("")

    if userchoice.strip().lower() == "c":

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

      mitm_arp_process = multiprocessing.Process(
        target=mitm_arp.main,
        args=(victim_ip, victim_mac, spoofed_ip_origin, spoofed_mac_origin, attacker_mac),
        daemon=True  # This will automatically terminate when main script exits
      )
      mitm_arp_process.start()

    elif userchoice.strip().lower() == "a":
      arppoison_monitor.main()

    elif userchoice.strip().lower() == "m":
      multipleMACdetect.main()

    elif userchoice.strip().lower() == "b":

      return


if __name__ == "__main__":
    main()