import json
import os

# Define the path for the counter file
COUNTER_FILE_PATH = 'decryption_counters.json'

def load_counters():
  # Load the counters from the JSON file.
  if os.path.exists(COUNTER_FILE_PATH):
    with open(COUNTER_FILE_PATH, 'r') as file:
      return json.load(file)
  else:
    return {}

def save_counters(counters):
  # Save the counters to the JSON file.
  with open(COUNTER_FILE_PATH, 'w') as file:
    json.dump(counters, file)

def initialize_counter(file_name, max_decryptions=1):
  # Initialize a counter for a given file with a max decryption limit.
  counters = load_counters()
  counters[file_name] = max_decryptions
  save_counters(counters)

def check_counter(file_name):
  # Check the current decryption count for a file.
  counters = load_counters()
  return counters.get(file_name, 0)  # Returns 0 if file is not found, assuming it can’t be decrypted

def decrement_counter(file_name):
  # Decrease the decryption counter by 1. Returns True if successful, False if counter is zero.
  counters = load_counters()
  if file_name in counters and counters[file_name] > 0:
    counters[file_name] -= 1
    save_counters(counters)
    return True  # Decryption allowed
  return False  # Decryption blocked