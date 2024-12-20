import hashlib
import os.path
import argparse
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from .keygen import generate_keyfile, generate_json_decrypt_counter_key

## Time for some lazy imports
dependency_decryption_counter = None

def load_dependent_decryption_counter():
  global dependency_decryption_counter
  if dependency_decryption_counter is None:
    try:
      import decryption_counter as d_c  # Import and alias for convenience
      dependency_decryption_counter = d_c
      print(f'Successfully imported {dependency_decryption_counter.__name__}.')
    except ImportError as e:
      print(f'Failed to import {dependency_decryption_counter.__name__}: {e}')
      raise

# Define the path for the counter file
JSON_COUNTER_FILE_PATH = 'decryption_counters.json'

def load_salt_and_key(key_file_name='my_sym.key'):
  try:
    with open(key_file_name, 'rb') as key_file:
      data = key_file.read()
      salt = data[:16]  # First 16 bytes are the salt
      key_and_hash = data[16:]  # The rest contains the key and password hash
      # Split key and password hash by the colon delimiter
      key, password_hash = key_and_hash.split(b':')
      key = key.decode()  # Fernet requires a base64-encoded string
      return salt, key, password_hash

  except FileNotFoundError:
    print(f"Error: The file '{key_file_name}' was not found.")
    return None, None, None
  except Exception as e:
    print(f"An error occurred while reading the file: {e}")
    return None, None, None


def encrypt_file(file_name, key, max_decryptions=1):
  fernet = Fernet(key)  # Initialize Fernet with the loaded key
  encrypted_file_name = file_name + '.encrypted'

  # Read and hash the original file data
  try:
    with open(file_name, 'rb') as file:
      original_data = file.read()
      file_hash = hashlib.sha256(original_data).digest()
  except Exception as e:
    print(f"An error occurred while reading the file: {e}")
    return

  encrypted_data = fernet.encrypt(original_data)

  # Append the hash to the encrypted data
  encrypted_data_with_file_hash = encrypted_data + b'::' + file_hash  # Adding separator (::) for easier parsing

  # Save the encrypted data with the hash
  try:
    with open(encrypted_file_name, 'wb') as encrypted_file:
      encrypted_file.write(encrypted_data_with_file_hash)
  except Exception as e:
    print(f"An error occurred while writing the file: {e}")
    print("Aborting...")
    return

  print(f"File '{file_name}' encrypted as '{encrypted_file_name}'")

  load_dependent_decryption_counter()

  if dependency_decryption_counter is not None:
    # Initialize the decryption counter for this file
    try:
      dependency_decryption_counter.initialize_counter(encrypted_file_name, max_decryptions)
      print(f"File '{file_name}' encrypted as '{encrypted_file_name}' with a max decryption count of {max_decryptions}")
    except Exception as e:
      print(f'Could not initialize counter: {e}')

  else:
    print(f'Error: Dependency {dependency_decryption_counter.__name__} was not loaded. Cannot initialize counter.')


def decrypt_file(encrypted_file_name, key):
  # Decrypt the file only if it passes the counter check.
  # Check if decryption is allowed by the counter
  load_dependent_decryption_counter()

  if not dependency_decryption_counter.decrement_counter(encrypted_file_name):
    print(
      f"Decryption of '{encrypted_file_name}' is not allowed. The file has already been decrypted the maximum number of times.")
    return
  fernet = Fernet(key)  # Create a Fernet instance with the derived key

  # Read the encrypted file
  try:
    with open(encrypted_file_name, 'rb') as encrypted_file:
      encrypted_data_with_file_hash = encrypted_file.read()
  except FileNotFoundError:
    print(f'"{encrypted_file_name}" not found. Please ensure that the path is correct.')
    return
  except Exception as e:
    print(f"An error occurred while reading the file: {e}")
    print("Aborting...")
    return

  # Separate encrypted data and hash
  try:
    encrypted_data, stored_file_hash = encrypted_data_with_file_hash.split(b'::')
  except ValueError:
    print("Encrypted file format is invalid or corrupted.")
    return

  try:
    # Decrypt the data
    decrypted_data = fernet.decrypt(encrypted_data)

    # Calculate hash of decrypted data
    new_hash = hashlib.sha256(decrypted_data).digest()

    # Verify integrity
    if new_hash != stored_file_hash:
      print("Integrity check failed! The file has been tampered with or corrupted.")
      return
    else:
      print("Integrity check passed.")

    # Save the decrypted data to a file (without the '.encrypted' extension)
    decrypted_file_name = encrypted_file_name.replace('.encrypted', '')
    with open(decrypted_file_name, 'wb') as decrypted_file:
      decrypted_file.write(decrypted_data)

      print(f"File '{encrypted_file_name}' decrypted successfully as '{decrypted_file_name}'")
  except Exception as e:
    print("Decryption failed. Incorrect password or corrupted file.")
    print(str(e))
  return


def validate_file_extension(file_path, required_extension):
  if not file_path.endswith(required_extension):
    print(f"Error: The file must have a '{required_extension}' extension.")
    return False
  return True


def check_password(userpass, stored_hash):
  """Check if the provided password matches the stored password hash."""
  # Hash the user-provided password
  hashed_password = hashlib.sha256(userpass.encode()).digest()

  # Base64 encode the hashed password
  hashed_password_base64 = urlsafe_b64encode(hashed_password).decode()

  # Ensure stored_hash is decoded for comparison
  if isinstance(stored_hash, bytes):
    stored_hash = stored_hash.decode()

  # Compare both base64-encoded hashes
  return hashed_password_base64 == stored_hash


def main():
  # Setup argument parser
  parser = argparse.ArgumentParser(description="File Encryption/Decryption Script. Uses a 16 byte salt precedence in the key-file")

  parser.add_argument(
    '-k', '--keyfile',
    type=str,
    help='Path to the key file (default: my_sym.key)'
  )
  parser.add_argument(
    '-g', '--generate',
    type=str,
    nargs='?',  # Optional argument
    const='my_sym.key',  # Default value if no file is provided
    help='Generate a new key for encryption/decryption (optionally provide a key name)'
  )
  parser.add_argument(
    '--max-decryptions',
    type=int,
    nargs='?',
    help='Set a maximum number of decryption attempts for the encrypted file'
  )

  dORe = parser.add_mutually_exclusive_group(required=False)
  dORe.add_argument(
    '-e', '--encrypt',
    type=str,
    help='Path to the file to encrypt'
  )
  dORe.add_argument(
    '-d', '--decrypt',
    type=str,
    help='Path to the file to decrypt'
  )

  # Parse arguments
  args = parser.parse_args()

  if not (args.encrypt or args.decrypt or args.generate):
    parser.print_help()
    return

  if args.generate and args.decrypt:
    print("The --generate option cannot be used with --decrypt. Exiting...")
    return

  key_file_name = None  # Initialize key_file_name as None

  # Check if a new key file should be generated
  if args.generate and not args.encrypt:
    key_file_name = args.generate if args.generate.endswith('.key') else args.generate + '.key'
    print('Generating key file...')
    try:
      generate_keyfile(key_file_name)  # Ensure the keygen function uses the new filename
      generate_json_decrypt_counter_key()
      print(f'New key file successfully generated as {key_file_name}')
      ## Old json counter file has to be deleted so there won't be any
      ## mismatch in keys when decrypting the encrypted stored data on load
      if os.path.exists(JSON_COUNTER_FILE_PATH):
        os.remove(JSON_COUNTER_FILE_PATH)
        print("Old decryption counters file removed!")
    except Exception as e:
      print(f"An error occurred during key generation: {e}")
      return
    except FileNotFoundError:
      print("Couldn't find the keygen.py script. Please make sure it's in the same directory or provide the correct path.")
      return

  # Use the specified key file or fall back to the generated one
  if args.keyfile:
    key_file_name = args.keyfile
  elif key_file_name is None:
    key_file_name = './my_sym.key'  # Default to 'my_sym.key' if no key file specified
  print(f'Using keyfile "{key_file_name}"')


  # Check if --max-decryptions is used without --encrypt
  if args.max_decryptions is not None and args.encrypt is None:
    parser.error(
      "--max-decryptions can only be used with --encrypt. Please use --encrypt to specify the file to encrypt."
    )

  ## This is a special case for when generate and encrypt args are used in conjunction
  ## It brought some tinker time to come up with this strict logic in crypto_tool
  ## to ensure that the correct keys are created and used for encryption on the fly

  if args.generate and args.encrypt:
    key_file_name = args.generate if args.generate.endswith('.key') else args.generate + '.key'
    print('Generating key file...')
    try:
      generate_keyfile(key_file_name)  # Ensure the keygen function uses the new filename
      generate_json_decrypt_counter_key()
      print(f'New key file successfully generated as {key_file_name}')
      ## Old json counter file has to be deleted so there won't be any
      ## mismatch in keys when decrypting the encrypted stored data on load
      if os.path.exists(JSON_COUNTER_FILE_PATH):
        os.remove(JSON_COUNTER_FILE_PATH)
        print("Old decryption counters file removed!")
    except Exception as e:
      print(f"An error occurred during key generation: {e}")
      return
    except FileNotFoundError:
      print("Couldn't find the keygen.py script. Please make sure it's in the same directory or provide the correct path.")
      return

    try:
      salt, key, password_hash = load_salt_and_key(key_file_name)
      if salt is None or key is None:
        print("Failed to load the salt and key")
        print("Make sure to have your key file in the same directory or set path and rerun the script")
        print("Aborting...")
        return
      else:
        print("Salt and key loaded successfully")
        ## No return here so the if args statement continue on successful load
    except ValueError as e:
      print(f"{e}: Failed to load the salt and key. Make sure you specified a keyfile to use")
      print("Aborting...")
      return

    if args.max_decryptions is None:
      try:
        encrypt_file(args.encrypt, key, 1)
        return
      except Exception as e:
        print(f'An error occurred during encryption: {e}')
        return
    else:
      try:
        encrypt_file(args.encrypt, key, args.max_decryptions)
        return
      except Exception as e:
        print("Here")
        print(f'An error occurred during encryption: {e}')
        return

  ## Here the args that has to be handled before have been managed
  ## Attempt to load the salt and key to use hereby forth
  try:
    salt, key, password_hash = load_salt_and_key(key_file_name)
    if salt is None or key is None:
      print("Failed to load the salt and key")
      print("Make sure to have your key file in the same directory or set path and rerun the script")
      print("Aborting...")
      return
    else:
      print("Salt and key loaded successfully")
  except ValueError as e:
    print(f"{e}: Failed to load the salt and key. Make sure you specified a keyfile to use")
    print("Aborting...")
    return

  # Encrypt or decrypt as needed
  if args.encrypt and not args.generate:
    print(f'Encrypting the file "{args.encrypt}"')
    if args.max_decryptions is None:
      encrypt_file(args.encrypt, key, 1)
    else:
      encrypt_file(args.encrypt, key, args.max_decryptions)

  if args.decrypt:
    if not validate_file_extension(args.decrypt, '.encrypted'):
      print("Decryption of non-encrypted file not possible.")
      print('Make sure that the correct file extension ".encrypted" is used')
      return

    print("Enter the password to decrypt the file:")
    numpasstries = 0

    while numpasstries < 3:
      userpass = input("")
      if not check_password(userpass, password_hash):
        print("Wrong password.")
        print(f"Number of retries {2 - numpasstries}:")
        numpasstries += 1

        if numpasstries == 3:
          print("Wrong password. Rerun the crypto-tool and generate a new key")
          return

      else:
        break

    print(f'Decrypting file "{args.decrypt}"')
    decrypt_file(args.decrypt, key)


if __name__ == "__main__":
    main()