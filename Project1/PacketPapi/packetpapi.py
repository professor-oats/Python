from . import multipleMACdetect
from . import arppoison_monitor
from . import gendict_knowndevices
from . import mitm_arp
from . import packetsniffer
from scapy.layers.l2 import getmacbyip, get_if_hwaddr
from scapy.all import conf, get_if_list
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

def is_valid_interface(in_interface):
  interfaces = get_if_list()
  if in_interface in interfaces:
    return True
  print("Please pick an interface running your MitM")
  return False

def main():
  print(BANNER)

  victim_ip, victim_mac, spoofed_ip_origin, spoofed_mac_origin, attacker_mac = (None,) * 5
  mitm_arp_process = None
  sniffing_process = None

  try:  ## Need this to terminate Daemons upon keyboard interrupting packetpapi
        ## Neat with this is that we can return to oatstools also on keyboard interrupt
        ## I have come to terms that this is the way to manage the subprocessing and works
        ## very well since we ensure accurate termination where has to be
        ## It's also fun to set a signal ignore for signal interrupting the subprocesses. xD

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
        if sniffing_process and sniffing_process.is_alive():
          print("Stopping precious sniffing process...")
          sniffing_process.terminate()
          sniffing_process.join()

        sniffing_interface = input("Enter the network interface to sniff on (e.g., eth0, wlan0): ")
        while True:
          if is_valid_interface(sniffing_interface):
            break
          sniffing_interface=input("")

        sniffing_process = multiprocessing.Process(target=packetsniffer.start_sniffing, args=(sniffing_interface,))
        sniffing_process.start()


      elif userchoice.strip().lower() == "a":
        try:
          arppoison_monitor.main()
        except KeyboardInterrupt:
          print("ARP monitoring stopped.")

      elif userchoice.strip().lower() == "m":
        multipleMACdetect.main()

      elif userchoice.strip().lower() == "g":
        gendict_knowndevices.main()

      ## Correctly terminating spawned subprocesses on [back] option and returning to Oatstools
      elif userchoice.strip().lower() == "b":
        print("Terminating Daemon mitm_arp_process...")
        if mitm_arp_process and mitm_arp_process.is_alive():
          print("Stopping ARP spoofing and restoring ARP tables...")
          mitm_arp_process.terminate()
          mitm_arp_process.join()
          mitm_arp.restore_arp(victim_ip, victim_mac, spoofed_ip_origin, spoofed_mac_origin, attacker_mac)  # Original spoofed_mac_here
          mitm_arp.restore_arp(spoofed_ip_origin, spoofed_mac_origin, victim_ip, victim_mac, attacker_mac)  # Original victim_mac_here

        print("Terminating Daemon sniffing_process...")
        if sniffing_process and sniffing_process.is_alive():
          print("Stopping the sniffing process...")
          sniffing_process.terminate()
          sniffing_process.join()
        return

  ## Correctuly terminating spawned subprocesses on KeyboardInterrupt and returning to Oatstools
  except KeyboardInterrupt:
    print("Terminating Daemon mitm_arp_process...")
    if mitm_arp_process and mitm_arp_process.is_alive():
      print("Stopping ARP spoofing and restoring ARP tables...")
      mitm_arp_process.terminate()
      mitm_arp_process.join()
      mitm_arp.restore_arp(victim_ip, victim_mac, spoofed_ip_origin, spoofed_mac_origin, attacker_mac)  # Original spoofed_mac_here
      mitm_arp.restore_arp(spoofed_ip_origin, spoofed_mac_origin, victim_ip, victim_mac, attacker_mac)  # Original victim_mac_here

    print("Terminating Daemon sniffing_process...")
    if sniffing_process and sniffing_process.is_alive():
      print("Stopping the sniffing process...")
      sniffing_process.terminate()
      sniffing_process.join()

    print("All subprocesses are terminated. Exiting \033[95mpacketpapi\033[0m.")
    return

if __name__ == "__main__":
    main()