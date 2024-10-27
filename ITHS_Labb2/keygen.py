from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode
from cryptography.hazmat.primitives import hashes
import os
import hashlib


def gen_key_from_password(password: str, salt: bytes) -> bytes:
  if not password:
      print("Empty password provided. Generating random Fernet key.")
      return Fernet.generate_key()

  # Derive a cryptographic key from a password and salt.
  kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,  # For use with Fernet encrypt: requires a 32-byte key
    salt=salt,
    iterations=100000,
    backend=default_backend()
  )
  return urlsafe_b64encode(kdf.derive(password.encode()))  # 64base encode for safer representation

def generate_keyfile(key_file_name='my_sym.key'):
  passcheck = ""
  while True:
    userpass = input("Input a password to generate a key, leave empty for no pass:\n")

    if userpass:
      passcheck = input("Retype the password:\n")

    if userpass == passcheck:
      break

    print("Error, passwords doesn't match. Try again.")

  salt = os.urandom(16)
  key = gen_key_from_password(userpass, salt)
  # Hash the password for storage (instead of storing the plain password)
  password_hash = urlsafe_b64encode(hashlib.sha256(userpass.encode()).digest())
  with open(key_file_name, 'wb') as key_file:
    key_file.write(salt + key + b':' + password_hash)
  print(f'Key, salt and password saved to "{key_file_name}"')

if __name__ == "__main__":
  generate_keyfile()