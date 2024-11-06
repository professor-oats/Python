from . import multipleMACdetect
from . import arppoison_monitor
from . import gendict_knowndevices
from . import mitm_arp
from . import packetsniffer
from scapy.layers.l2 import getmacbyip, get_if_hwaddr
from scapy.all import conf
import multiprocessing
import ipaddress

BANNER = """
\033[34m#######################################
###  \033[0m-  Welcome to \033[95mpacketpapi\033[0m  - \033[34m   ###
###  \033[0myour personal packet commander\033[34m ###
#######################################\033[0m"""

CATEGORIES = """
\033[1m\033[95mOFFENSIVE SCRIPTS\033[0m
[\033[97mC\033[0m]ustom MitM ARP - Construct a MitM between two network devices
[\033[97mP\033[0m]acketSniffer - Use on the interface where the MitM is positioned


\033[1m\033[95mDEFENSIVE SCRIPTS\033[0m
[\033[97mA\033[0m]RP-poison monitor - MitM mitigate
[\033[97mM\033[0m]ultiple MAC detect - MitM mitigate
[\033[97mG\033[0m]enDict KnownDevices - Complement ARP cache by generating dict of known network devices

\033[1m\033[95mMENU COMMANDS\033[0m
[\033[97mB\033[0m]ack"""

# Just a check to see if the IP is correctly formatted
def is_valid_ip(target):
  try:
    ipaddress.ip_address(target)
    return True
  except ValueError:
    return False

def main():
  print(BANNER)

  victim_ip, victim_mac, spoofed_ip_origin, spoofed_mac_origin, attacker_mac = (None,) * 5
  mitm_arp_process = None

  try:  ## It is what it is ... need this to terminate Daemons upon keyboard interrupting packetpapi
        ## Neat with this is that we can return to oatstools also on keyboard interrupt
        ## Good practice?? I wouldn't say ... Hostaging users like this
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

        if mitm_arp_process and mitm_arp_process.is_alive():
          print("Stopping previous ARP spoofing process...")
          mitm_arp_process.terminate()
          mitm_arp_process.join()

        mitm_arp_process = multiprocessing.Process(
          target=mitm_arp.main,
          args=(victim_ip, victim_mac, spoofed_ip_origin, spoofed_mac_origin, attacker_mac)
          #daemon=True  # This will automatically terminate when main script exits
        )
        mitm_arp_process.start()

      elif userchoice.strip().lower() == "p":
        packetsniffer.sniffing_process()

      elif userchoice.strip().lower() == "a":
        try:
          arppoison_monitor.main()
        except KeyboardInterrupt:
          print("ARP monitoring stopped.")

      elif userchoice.strip().lower() == "m":
        multipleMACdetect.main()

      elif userchoice.strip().lower() == "g":
        gendict_knowndevices.main()

      elif userchoice.strip().lower() == "b":
        if mitm_arp_process and mitm_arp_process.is_alive():
          print("Stopping ARP spoofing and restoring ARP tables...")
          mitm_arp_process.terminate()
          mitm_arp_process.join()
          mitm_arp.restore_arp(victim_ip, victim_mac, spoofed_ip_origin, spoofed_mac_origin, attacker_mac)  # Original spoofed_mac_here
          mitm_arp.restore_arp(spoofed_ip_origin, spoofed_mac_origin, victim_ip, victim_mac, attacker_mac)  # Original victim_mac_here
          print("Terminating Daemon mitm_arp_process...")
        return

  except KeyboardInterrupt:
    print("Terminating Daemon mitm_arp_process...")
    if mitm_arp_process and mitm_arp_process.is_alive():
      print("Stopping ARP spoofing and restoring ARP tables...")
      mitm_arp_process.terminate()
      mitm_arp_process.join()
      mitm_arp.restore_arp(victim_ip, victim_mac, spoofed_ip_origin, spoofed_mac_origin, attacker_mac)  # Original spoofed_mac_here
      mitm_arp.restore_arp(spoofed_ip_origin, spoofed_mac_origin, victim_ip, victim_mac, attacker_mac)  # Original victim_mac_here
    print("Arp spoofer terminated. Exiting \033[95mpacketpapi\033[0m.")
    return

if __name__ == "__main__":
    main()