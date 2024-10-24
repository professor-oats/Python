import hashlib
import sys
import argparse
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from keygen import generate_keyfile


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


def encrypt_file(file_name, key):
  fernet = Fernet(key)  # Initialize Fernet with the loaded key

  try:
    with open(file_name, 'rb') as file:
      original_data = file.read()
  except Exception as e:
    print(f"An error occurred while reading the file: {e}")
    return

  encrypted_data = fernet.encrypt(original_data)

  try:
    with open(file_name + '.encrypted', 'wb') as encrypted_file:
      encrypted_file.write(encrypted_data)
  except Exception as e:
    print(f"An error occurred while writing the file: {e}")

  print(f"File '{file_name}' encrypted as '{file_name}.encrypted'")


def decrypt_file(encrypted_file_name, key):
  fernet = Fernet(key)  # Create a Fernet instance with the derived key

  # Read the encrypted file
  try:
    with open(encrypted_file_name, 'rb') as encrypted_file:
      encrypted_data = encrypted_file.read()
  except FileNotFoundError:
    print(f'"{encrypted_file_name}" not found. Please ensure that the path is correct.')
    return
  except Exception as e:
    print(f"An error occurred while reading the file: {e}")
    print("Aborting...")
    exit()

  try:
    # Decrypt the data
    decrypted_data = fernet.decrypt(encrypted_data)

    # Save the decrypted data to a file (without the '.encrypted' extension)
    decrypted_file_name = encrypted_file_name.replace('.encrypted', '')
    with open(decrypted_file_name, 'wb') as decrypted_file:
      decrypted_file.write(decrypted_data)

      print(f"File '{encrypted_file_name}' decrypted successfully as '{decrypted_file_name}'")
  except Exception as e:
    print("Decryption failed. Incorrect password or corrupted file.")
    print(str(e))


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
    help='Generate a new key for encryption/decryption (optionally provide a file name)'
  )

  parser.add_argument(
    '-e', '--encrypt',
    type=str,
    help='Path to the file to encrypt'
  )

  parser.add_argument(
    '-d', '--decrypt',
    type=str,
    help='Path to the file to decrypt'
  )

  # Parse arguments
  args = parser.parse_args()

  if len(sys.argv) == 1:
    parser.print_help()  # Show help if no arguments are passed
    sys.exit(1)  # Exit the script

  key_file_name = None  # Initialize key_file_name as None

  # Check if a new key file should be generated
  if args.generate:
    key_file_name = args.generate if args.generate.endswith('.key') else args.generate + '.key'
    print('Generating key file...')
    try:
      generate_keyfile(key_file_name)  # Ensure the keygen function uses the new filename
      print(f'New key file successfully generated as {key_file_name}')
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
    key_file_name = 'my_sym.key'  # Default to 'my_sym.key' if no key file specified

  # Attempt to load the salt and key
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
  if args.encrypt:
    print(f'Encrypting the file "{args.encrypt}"')
    encrypt_file(args.encrypt, key)

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