from . import multipleMACdetect
from . import arppoison_monitor
from . import gendict_knowndevices
from . import mitm_arp
from . import packetsniffer
from . import DNSpoisoner
from . import spawn_decoy_site
from scapy.layers.l2 import getmacbyip, get_if_hwaddr
from scapy.all import conf, get_if_list
import multiprocessing
import ipaddress
import time

## Initialize a logger for PacketPapi's processes perhaps??

BANNER = """
\033[34m#######################################
###  \033[0m-  Welcome to \033[95mpacketpapi\033[0m  - \033[34m   ###
###  \033[0myour personal packet commander\033[34m ###
#######################################\033[0m"""

CATEGORIES = """
\033[1m\033[95mOFFENSIVE SCRIPTS\033[0m
[\033[97mC\033[0m]ustom MitM ARP - Construct a MitM between two network devices
[\033[97mS\033[0m]pawn http decoy site - Clone a website by url and deploy an SSL-stripped http server
[\033[97mD\033[0m]NSpoisoner - Begin DNS poisoning on target, example spoofing domain to your decoy site
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

def terminate_running_process(in_process):
  print(f"Terminating Daemon {in_process.name}...")
  print(f"Stopping the {in_process.name} process...")
  in_process.terminate()
  in_process.join()
  return

def main():
  print(BANNER)

  victim_ip, victim_mac, spoofed_ip_origin, spoofed_mac_origin, attacker_mac = (None,) * 5
  mitm_arp_process = None
  sniffing_process = None
  dns_poison_process = None
  decoy_server_process = None

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
          name="mitm_arp_process",
          args=(victim_ip, victim_mac, spoofed_ip_origin, spoofed_mac_origin, attacker_mac)
          #daemon=True  # This will automatically terminate when main script exits
        )
        mitm_arp_process.start()

      elif userchoice.strip().lower() == "d":
        if not mitm_arp_process or not mitm_arp_process.is_alive():
          print("None running mitm_arp process found. Do you wish to continue? (Y)"
                "Or wish to go back and start a mitm for spoof priority? (N)")
          start_dns_poison = input("")
          if not start_dns_poison.strip().lower() == "y":
            print("Going back...")
            continue

        victim_ip = input("Declare the IP of the victim you want to target:\n")
        spoof_domain = input("Enter the target domain you like to redirect from:\n")
        spoof_ip = input("Enter the IP address you like to redirect to:\n")

        dns_poison_process = multiprocessing.Process(target=DNSpoisoner.main, name="dns_poison_process", args=(victim_ip, spoof_domain, spoof_ip))
        dns_poison_process.start()

      elif userchoice.strip().lower() == "s":

        if decoy_server_process and decoy_server_process.is_alive():
          print("Stopping previous decoy server...")
          decoy_server_process.terminate()
          decoy_server_process.join()


        quick_clone = input("Do you want to make a quick clone? (Increased risk of IP block on domain) (YES/NO)\n" )
        if quick_clone.strip().lower() != "yes":
          quick_clone = "no"
        ## Will not make a try for correct url here since want to able cloning from custom sources (local domains etc)
        decoy_url = input("Input the URL you want to clone as a decoy:\n")
        port = 80
        decoy_server_process = multiprocessing.Process(target=spawn_decoy_site.main, name="decoy_server_process", args=(decoy_url, port, quick_clone,))
        decoy_server_process.start()

      elif userchoice.strip().lower() == "p":
        if sniffing_process and sniffing_process.is_alive():
          print("Stopping previous sniffing process...")
          sniffing_process.terminate()
          sniffing_process.join()

        sniffing_interface = input("Enter the network interface to sniff on (e.g., eth0, wlan0): ")
        while True:
          if is_valid_interface(sniffing_interface):
            break
          sniffing_interface=input("")

        sniffing_process = multiprocessing.Process(target=packetsniffer.start_sniffing, name="sniffing_process", args=(sniffing_interface,))
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
      ## Note: Realised this totally mimics the terminations on Exception KeyboardInterrupt
      ## Good practice is to write an own exception class and raising that here,
      ## however that means i must move the process vars and set them as globals,
      ## give myself the slack to just raise KeyboardInterrupt here since mainscript
      ## oatstools imports and call PacketPapi main properly already

      elif userchoice.strip().lower() == "b":
        raise KeyboardInterrupt

  ## Correctly terminating spawned subprocesses on KeyboardInterrupt and returning to Oatstools
  except KeyboardInterrupt:
    if mitm_arp_process and mitm_arp_process.is_alive():
      terminate_running_process(mitm_arp_process)
      mitm_arp.restore_arp(victim_ip, victim_mac, spoofed_ip_origin, spoofed_mac_origin, attacker_mac)  # Original spoofed_mac_here
      mitm_arp.restore_arp(spoofed_ip_origin, spoofed_mac_origin, victim_ip, victim_mac, attacker_mac)  # Original victim_mac_here

    if decoy_server_process and decoy_server_process.is_alive():
      # Graceful termination of servers
      # HTTPS
      if spawn_decoy_site.https_server:
        spawn_decoy_site.https_server.shutdown()
        spawn_decoy_site.https_server.server_close()  # Close the HTTPS server's socket
        print("The HTTPS redirect server has been shutdown")
      if spawn_decoy_site.https_thread:
        spawn_decoy_site.https_thread.shutdown()  # Stop the HTTPS thread
        print("Thread cleared")

      # HTTP
      if spawn_decoy_site.http_server:
        spawn_decoy_site.http_server.shutdown()
        spawn_decoy_site.http_server.server_close()  # Close the HTTP server's socket
        print("The HTTP decoy server has been shutdown")
      if spawn_decoy_site.http_thread:
        spawn_decoy_site.http_thread.shutdown()  # Stop the HTTPS server
        spawn_decoy_site.http_thread.server_close()  # Close the HTTPS server's socket
        print("Thread cleared")

      terminate_running_process(decoy_server_process)

    if dns_poison_process and dns_poison_process.is_alive():
      terminate_running_process(dns_poison_process)

    if sniffing_process and sniffing_process.is_alive():
      terminate_running_process(sniffing_process)

    print("All subprocesses are terminated. Exiting \033[95mpacketpapi\033[0m.")
    return

if __name__ == "__main__":
    main()