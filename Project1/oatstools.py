from PacketPapi import packetpapi
from OatsNmapper import nmapper
import simple_fileserver
import subprocess


BANNER = """
\033[34m#######################################
###  \033[93m-\033[0m This is the main menu of \033[93m-\033[34m   ###
###     \033[93m••\033[0m Oat\033[93m'\033[0ms Toolbox\033[93m ••\033[34m         ###
#######################################\033[0m"""

DISPLAYUSERCHOICES = """
\033[95mNETWORKING\033[0m
[\033[97mP\033[0m]acketpapi - Scripts for package sniffing, manipulation and spoofing
[\033[97mO\033[0m]at's Nmapper - Wrapper for Nmap with multithread support

\033[95mENCRYPTION/DECRYPTION/PASSWORD MANAGEMENT\033[0m
[\033[97mC\033[0m]rypto_tool - Call a script for file encryption and decryption

\033[95mFILE MANAGEMENT\033[0m
[\033[97mS\033[0m]imple_fileserver - Create a simple file server over local network

\033[95mMENU COMMANDS\033[0m
[\033[97mE\033[0m]xit"""

def main():
  print(BANNER)

  while True:
    print(DISPLAYUSERCHOICES)
    userchoice = input("")

    if userchoice.strip().lower() == "p":
      packetpapi.main()

    elif userchoice.strip().lower() == "o":
      nmapper.main()

    elif userchoice.strip().lower() == "c":
      print("Launching crypto_tool help menu...\n")
      subprocess.run(["python", "-m", "CryptoTool.crypto_tool", "--help"])

      action = input("crypto_tool ")

      # Run the crypto_tool with the user's inputs
      print("Running crypto_tool with args:", action)
      subprocess.run(["python", "-m", "CryptoTool.crypto_tool", action])
      input("Continue...")

    elif userchoice.strip().lower() == "s":
      simple_fileserver.main()

    elif userchoice.strip().lower() == "e":
      return


if __name__ == "__main__":
    main()