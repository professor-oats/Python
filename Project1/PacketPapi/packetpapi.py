from . import multipleMACdetect
from . import arppoison_monitor
from . import mitm_arp

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

def main():
  print(BANNER)

  while True:
    print(CATEGORIES)
    userchoice = input("")

    if userchoice.strip().lower() == "c":
      mitm_arp.main()

    elif userchoice.strip().lower() == "a":
      arppoison_monitor.main()

    elif userchoice.strip().lower() == "m":
      multipleMACdetect.main()

    elif userchoice.strip().lower() == "b":
      return


if __name__ == "__main__":
    main()