import json
import os
from cryptography.fernet import Fernet

# Define the path for the counter file + json key file
JSON_COUNTER_FILE_PATH = 'decryption_counters.json'
JSON_KEY_FILE_PATH = 'json_decrypt_counter.key'

def load_key():
  try:
    with open(JSON_KEY_FILE_PATH, 'rb') as key_file:
      data = key_file.read()
      return data
  except FileNotFoundError:
    print(f'Error: The file "json_decrypt_counter.key" was not found.')
    return None
  except Exception as e:
    print(f'An error occurred while reading the file: {e}')
    return None

## Load the key into a fernet instance
d_key = load_key()
if d_key is None:
    print("Failed to load the encryption key. Exiting...")
    exit(1)

fernet_json = Fernet(d_key)

def load_counters():
  # Load the counters from the JSON file
  if os.path.exists(JSON_COUNTER_FILE_PATH):
    try:
      with open(JSON_COUNTER_FILE_PATH, 'rb') as file:  # Open in binary mode for encrypted data
        encrypted_data = file.read()
        decrypted_data = fernet_json.decrypt(encrypted_data)  # Decrypt the data
        json_data = decrypted_data.decode('utf-8')
        return json.loads(json_data)  # Load as JSON
    except FileNotFoundError:
      print("File not found")
    except Exception as e:
      print(f"An error occurred while reading the file: {e}")
  else:
    return {}  # Returns an empty dictionary to store decrypt counters in if no current file data exists
               # Ensuring in the crypto_tool that this is also the case when generating new keys

def save_counters(counters):
  # Save the counters to the JSON file
  json_data = json.dumps(counters).encode()  # Convert to bytes
  encrypted_data = fernet_json.encrypt(json_data)  # Encrypt the data
  with open(JSON_COUNTER_FILE_PATH, 'wb') as file:  # Open in binary mode for encrypted data
    file.write(encrypted_data)  # Save the encrypted data

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