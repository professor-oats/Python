import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import socket
from datetime import datetime
import os
import json
import re

def run_nmap(target, *flags_in, save_results=False):
  command = ['nmap', target] + list(flags_in)
  print(f"Running command for {target}: {' '.join(command)}")

  if save_results:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    command += ['-oA', f'{target}_{timestamp}']

  try:
    result = subprocess.run(command, capture_output=True, text=True)
    return target, result.stdout, None  # Return target, stdout and None for error
  except subprocess.CalledProcessError as e:
    return target, None, str(e)


def is_valid_ip_or_hostname(target):
  try:
    ipaddress.ip_address(target)
    return True
  except ValueError:
    try:
      socket.gethostbyname(target)
      return True
    except socket.error:
      return False


def is_valid_port_range(port_range):
  # Updated regex to allow open-beginning ('-80') and open-ending ('80-') ranges
  pattern = r'^(?:[0-9]{0,5}-[0-9]{0,5})$'
  match = re.match(pattern, port_range)

  if match:
    ports = port_range.split('-')

    # Handle open-beginning range like '-80' (assume start port is 0)
    if ports[0] == '':
      start_port = 0
    else:
      start_port = int(ports[0])

    # Handle open-ending range like '80-'
    if ports[1] == '':
      end_port = 65535
    else:
      end_port = int(ports[1])

    # Validate that both start and end ports are in the valid range
    return 0 <= start_port <= 65535 and 0 <= end_port <= 65535 and start_port <= end_port

  return False


def is_valid_port_list(port_list):
  # Regular expression to allow open-start, open-end ranges and individual ports separated by commas
  pattern = r'^([0-9]{1,5}|[0-9]{0,5}-[0-9]{0,5})(,([0-9]{1,5}|[0-9]{0,5}-[0-9]{0,5}))*$'
  match = re.match(pattern, port_list)

  if match:
    ports = port_list.split(',')
    for port in ports:
      if '-' in port:  # Check for ranges
        if not is_valid_port_range(port):
          return False
      else:  # Check for individual ports
        port_num = int(port)
        if not (0 <= port_num <= 65535):
          return False
    return True
  return False

## General scooper that nullify args consisting of letters
def is_valid_arg_general(in_arg):
  return in_arg.isdigit() or is_valid_port_range(in_arg) or is_valid_port_list(in_arg)

def extractIPfromJSON(data):
  valid_targets = set()

  if isinstance(data, dict):
    for key, value in data.items():
      if isinstance(value, (dict, list)):
        # Recursively extract from nested dicts or lists
        valid_targets.update(extractIPfromJSON(value))
      elif isinstance(value, str):
        # Check if the value is a valid IP or hostname
        if is_valid_ip_or_hostname(value):
          valid_targets.add(value)
  elif isinstance(data, list):
    for item in data:
      if isinstance(item, (dict, list)):
        # Recursively extract from nested dicts or lists
        valid_targets.update(extractIPfromJSON(item))
      elif isinstance(item, str):
        # Check if the item is a valid IP or hostname
        if is_valid_ip_or_hostname(item):
          valid_targets.add(item)

  return valid_targets

def set_target_ips():
  while True:
    user_choice = input("""Do you want to load IPs/hostnames from
a file (f) or input IPs manually (m) as a comma separated list? (m/f): """)

    if user_choice.lower() == 'm':
      targets = input("Enter the target IPs or hostnames seperated by commas or whitespace:\n")

      # Check if there are any altogether
      if targets:
        potential_targets = [target.strip() for target in targets.replace(',', ' ').split()]
        valid_targets = set()

        for target in potential_targets:
          # Check if IP address is valid
          if is_valid_ip_or_hostname(target):
            valid_targets.add(target)
          else:
            print(f'"{target}" is not a valid IP address or hostname and will be skipped...')

        if valid_targets:
          return valid_targets
        else:
          print("No valid IPs or hostnames were provided. Please enter at least one valid IP or hostname.")

      else:
        print("Input empty. Please try again.")

    elif user_choice.lower() == 'f':
      while True:
        file_path = input("Enter the path to the file containing target IPs:\n")
        if not os.path.isfile(file_path):
            print("Error: The file does not exist. Please check the path and try again.")
            continue

        try:
          if file_path.endswith('.json'):
            with open(file_path, 'r') as readIPfile:
              data = json.load(readIPfile)
              valid_targets = extractIPfromJSON(data)
              return valid_targets

          else:
            potential_targets = []
            with open(file_path, 'r') as readIPfile:
              for line in readIPfile:
                items = line.strip().replace(',', ' ').split()
                potential_targets.extend([item for item in items if item])

      # Check valids outside with open to reduce I/O overhead
          valid_targets = set()
          for target in potential_targets:
            # Check if IP address is valid
            if is_valid_ip_or_hostname(target):
              valid_targets.add(target)
            else:
              print(f'"{target}" in file is not a valid IP address or hostname and will be skipped.')

          if valid_targets:
            return valid_targets

          else:
            print("The file contained no valid IPs. Please provide a file with valid IPs.")

        except FileNotFoundError:
          print(f'"{file_path}" not found. Please ensure that the path is correct.')
        except Exception as e:
          print(f"An error occurred while reading the file: {e}")

    else:
      print("Invalid choice. Please select 'm' for manual input or 'f' for file input")


## Make a satisfied prompt to give the user the option to redo?
def custom_scan():
  print("***** Here you can customize what type of scans you want to do *****")
  scan_flags = []

  while True:
    print("""Pick from the list of options to add them to your scan:
1. TCP Connect Scan (-sT)
2. SYN Scan (-sS)
3. Version Detection (-sV)
4. OS Detection (-O)
5. Default Scripts (-sC)
6. Timing Template 4 (-T4)
7. Add your own flags
8. Display command flags set
9. Add flags for full scan on all ports (Slower)
10. Clear all flags
11. Display all options
0. Done""")

    while True:
      try:
        picked_scan_type = int(input(""))
        if not 0 <= picked_scan_type < 12:
          raise ValueError
        break
      except ValueError:
        print("Wrong input. Please make a choice 0-11")

    ## Mimics set functionality
    ## Refinement further on could be to use set instead
    if picked_scan_type == 1:
      if not '-sT' in scan_flags:
        scan_flags.append('-sT')
        print("Flag -sT added")
    if picked_scan_type == 2:
      if not '-sS' in scan_flags:
        scan_flags.append('-sS')
        print("Flag -sS added")
    if picked_scan_type == 3:
      if not '-sV' in scan_flags:
        scan_flags.append('-sV')
        print("Flag -sV added")
    if picked_scan_type == 4:
      if not '-O' in scan_flags:
        scan_flags.append('-O')
        print("Flag -O added")
    if picked_scan_type == 5:
      if not '-sC' in scan_flags:
        scan_flags.append('-sC')
        print("Flag -sC added")
    if picked_scan_type == 6:
      if not '-T4' in scan_flags:
        scan_flags.append('-T4')
        print("Flag -T4 added")
    if picked_scan_type == 7:
      scan_flags = process_custom_flags(scan_flags)
    if picked_scan_type == 8:
      print(scan_flags)
    if picked_scan_type == 9:
      fullscan_flags = ['-sS', '-sV', '-O', '-p-', '--script=default', '--script-args=unsafe=1', '-T4']
      for flag in fullscan_flags:
        if not flag in scan_flags:
          scan_flags.append(flag)
          print(f"Flag {flag} added")
        else:
          print(f'Flag {flag} already added"')
    if picked_scan_type == 10:
      scan_flags = []
    if picked_scan_type == 11:
      print(VALID_NMAP_FLAGS)
    if picked_scan_type == 0:
      while True:
        save_prompt = input("Do you wish to save the nmap results to a file,Y/N?\n")
        if save_prompt.lower() == 'y':
          save_results = True
          print("Results will be saved to files: [target]_[timestamp].nmap|gnmap|xml")
          input("Press enter to continue\n")
          break
        elif save_prompt.lower() == 'n':
          save_results = False
          print("Results will not be saved to files but you will see the output")
          input("Press enter to continue\n")
          break
        else:
          print("Invalid input. Please try again.")

      return scan_flags, save_results


## Add more flags as seeing fit
## Source: https://svn.nmap.org/nmap/docs/nmap.usage.txt
## Cool approach would be to extract all flags from there but current time/skill span won't suffice
## Will opt out flags that require file arguments to limit the need for try on these
## Will change set into dictionary so we can print comments as keywords when user asks for
## (if has_time)

VALID_NMAP_FLAGS = {

  ### HOST DISCOVERY ###
  '-sL', '-sn', '-Pn', '-PS', '-PA', '-PU', '-PY', '-PE', '-PP', '-PM', '-PO', '-n', '-R', '--dns-servers',
  '--system-dns', '--traceroute', '--exclude'
                  
  ### SCAN TECHNIQUES ###
  '-sS', '-sT', '-sA', '-sW', '-sM', '-sU', '-sN', '-sF', '-sX', '--scanflags', '-sI', '-sY', '-sZ',
  '-sO', '-b',

  ### PORT SPECIFICATION AND SCAN ORDER ###
  '-p', '--exclude-ports', '-F', '-r', '--top-ports', '--port-ratio',

  ### SERVICE/VERSION/OS DETECTION ###
  '-sV', '--version-intensity', '--version-light', '--version-all', '--version-trace',
  '-O', '--osscan-limit', '--osscan-guess',

  ### SCRIPT SCAN ###
  '-sC', '--script', '--script=', '--script-args', '--script-args=',  '--script-trace',
  '--script-help', '--script-help=',

  ### TIMING AND PERFORMANCE ###
  '-T0', '-T1', '-T2', '-T3', '-T4', '-T5', '--min-rtt-timeout', '--max-rtt-timeout',
  '--initial-rtt-timeout', '--max-retries', '--host-timeout', '--scan-delay', '--max-scan-delay',
  '--min-rate', '--max-rate',

  ### Firewall/IDS EVASION AND SPOOFING ###
  '-f', '--mtu', '-D', '-S', '-e', '-g', '--source-port', '--proxies', '--data', '--data-string', '--data-length',
  '--ip-options', '--ttl', '--spoof-mac', '--badsum',

  ## Omits the flag -oA since will give user option to save output in run_nmap()
  ### OUTPUT AND MISC ###
  '-v', '-vv', '-d','-dd', '--reason', '--open', '--packet-trace', '--iflist',
  '-6', '-A', '--send-eth', '--send-ip', '--privileged', '--unprivileged', '-V', '-h',
  '--disable-arp-ping'

}


REQUIRES_ARG_FLAGS = {

  ### HOST DISCOVERY ###
  '--dns-servers',
  
  ### SCAN TECHNIQUES ###
  '--scanflags', '-sI', '-b',
  
  ### PORT SPECIFICATION AND SCAN ORDER ###
  '-p', '--exclude-ports', '--top-ports', '--port-ratio',
                                                        
  ### SERVICE/VERSION/OS DETECTION ###
  '--version-intensity', '--osscan-limit', '--osscan-guess',

  ### TIMING AND PERFORMANCE ###
  '--min-rtt-timeout', '--max-rtt-timeout', '--initial-rtt-timeout', '--max-retries',
  '--host-timeout', '--scan-delay', '--max-scan-delay', '--min-rate', '--max-rate',
  
  ### Firewall/IDS EVASION AND SPOOFING ###
  '--mtu', '-D', '-S', '-e', '-g', '--source-port', '--proxies', '--data', '--data-string', '--data-length',
  '--ip-options', '--ttl', '--spoof-mac',

}


def process_custom_flags(scan_flags):

  while True:
    custom_flags = input("Enter any additional Nmap flags (or press enter to skip):\n")
    if not custom_flags:
      break

    flags = custom_flags.split()  # Split input args to get the flags + flagargs

    # Initialize skippers for args
    # First had skip_twice since thought there could be
    # cases where two flag arguments had to be handled
    # Keep it as comment since nice alternative if ever needed
    # "twice" is only name conventionalized, both skips need to be set for twice skip

    skip_next = False
    #skip_twice = False

    for i, flag in enumerate(flags):
      if skip_next:
     #   if skip_twice:
      #    skip_twice = False
       #   continue
        skip_next = False
        continue

      # Check if a flag or an argument
      if flag[0].isalpha() or flag.startswith('-'):
        # Normalize the flags
        if not flag.startswith('-'):
          dash_flag1_begin = f'-{flag[0]}'
          dash_flag1_rest = flag[1:]
          dash_flag2_begin = f'-{flag[0:2]}'
          dash_flag2_rest = flag[2:]
          double_dash_flag = f'--{flag[0:]}'
          if dash_flag1_begin in VALID_NMAP_FLAGS:
            print(f'"{flag}" normalized to "{dash_flag1_begin + dash_flag1_rest}".')
            flag = dash_flag1_begin + dash_flag1_rest
          elif dash_flag2_begin in VALID_NMAP_FLAGS:
            print(f'"{flag}" normalized to "{dash_flag2_begin +dash_flag2_rest}".')
            flag = dash_flag2_begin + dash_flag2_rest
          elif double_dash_flag in VALID_NMAP_FLAGS:
            print(f'"{flag}" normalized to "{double_dash_flag}".')
            flag = double_dash_flag

        double_dash_flag = f'--{flag[1:]}'
        if double_dash_flag in VALID_NMAP_FLAGS:
          print(f'"{flag}" normalized to "{double_dash_flag}".')
          flag = double_dash_flag

        # Handle --script flag to ensure correct form even if user input --script default
        # Mini-globber
        if flag.startswith('--script') and not flag[-1] == '=':
          print(f'"{flag}" normalized to "{flag}="')
          flag = flag + '='
          if i + 1 < len(flags):  # Check if there is a next argument for the flag
            arg = flags[i + 1]
            if not arg.startswith('-'):  # Ensure that the next item is an argument and not a flag
              print(f'Using script arg: {arg}')
              scan_flags.extend([flag + arg])  # Extend the valid into the list
              skip_next = True  # Skip flagcheck on the argument
              continue

        # Handle flags starting with '-p'
        if flag.startswith('-p'):
          possible_arg = flag[2:]
          if not possible_arg:
            scan_flags.append(flag)
            continue
          if is_valid_arg_general(possible_arg):
            print(f'"{possible_arg}" taken as argument for "{flag[0:2]}"')
            scan_flags.append(flag)
            continue
          print(f'"{possible_arg} is not a possible argument for "{flag[0:2]}". Skipping')
          continue

        # Handle flags starting with '-P'. Let user have space between flag and flag arg
        if flag.startswith('-P'):
          if len(flag) == 3 and i + 1 < len(flags):
            if flag[0:3] in VALID_NMAP_FLAGS:
              possible_arg = flags[i + 1]
              if is_valid_arg_general(possible_arg):
                scan_flags.append(f'{flag}{possible_arg}')  # Extend the valid into the list
                print(f'{possible_arg} taken as argument for {flag}"')
                skip_next = True  # Skip flagcheck on the argument
                continue
            else:
              print(f'"{flag} is Invalid -P* flag, skipping"')
              continue

          # Handle possible arguments for '-P' flags. Ok use of code dup
          possible_arg = flag[3:]
          if not possible_arg:
            scan_flags.append(flag)
            continue
          if is_valid_arg_general(possible_arg):
            print(f'"{possible_arg}" taken as argument for "{flag[0:3]}"')
            scan_flags.append(flag)
            continue
          print(f'"{possible_arg} is not a possible argument for "{flag[0:3]}". Skipping')
          continue

        # Check if flag is valid and requires arguments
        # Thing to improve - check how many flag dependent wrong checks is_valid_arg_general() would generate
        if flag in VALID_NMAP_FLAGS:
          if flag in REQUIRES_ARG_FLAGS:

            # Handle arguments
            if i + 1 < len(flags):  # Check if there is a next argument for the flag
              arg = flags[i + 1]
              if not arg.startswith('-') and is_valid_arg_general(arg):  # Ensure that the next item is an argument and not a flag
                scan_flags.extend([flag, arg])  # Extend the valid into the list
                skip_next = True  # Skip flagcheck on the argument

              else:
                print(f'flag "{flag}" requires an argument, but none provided. Skipping')
                continue

            else:
              print(f'flag "{flag}" requires an argument, but none provided. Skipping')
              continue

          else:
            if flag not in scan_flags:
              scan_flags.append(flag)
            else:
              print(f'Flag "{flag}" is already included')

        else:
          print(f'Invalid flag "{flag}" ignored.')

    add_more = input("Would you like to add more flags? (y/n): ").strip().lower()
    if add_more != 'y':
      break

  return scan_flags


def main():
  while True:
    print("Hello and Welcome to Oat's Nmapper, a tool-assisted nmap with multithread support")
    print("Some nmap options will not be configured, please run nmap for the full experience")
    print("""How many threads do you want to use?
  1. Single Nmapper session
  2. Double Threads
  3. Triple Threads
  4. Exit the Tool""")

    while True:
      try:
        thread_choice = int(input(""))
        if not 0 < thread_choice < 5:
          raise ValueError
        break
      except ValueError:
        print("Wrong input. Please make a choice 1-4")

    if thread_choice == 4:
      return

    ips_to_scan = set_target_ips()
    flags_to_scan, save_results = custom_scan()
    scan_results = []

    if flags_to_scan:
      with ThreadPoolExecutor(max_workers=thread_choice) as executor:
        future_to_scan = {executor.submit(run_nmap, target, *flags_to_scan, save_results=save_results): target for target in ips_to_scan}
        for future in as_completed(future_to_scan):
          target = future_to_scan[future]

          try:
            target, output, error = future.result()
            if error:
              print(f"Scan failed for {target}: {error}")
            else:
              print(f"Scan result for {target}:\n{output}")
            scan_results.append((target, output, error))

          except Exception as e:
            print(f"Error retrieving result for {target}: {str(e)}")

      print("Scans completed.")
      want_exit=input("Press enter to continue or type exit to exit: ")

    else:
      want_exit=input("No options were picked for nmap. Press enter to go again or type exit to exit")

    if want_exit == 'exit':
      return


if __name__ == '__main__':
  main()