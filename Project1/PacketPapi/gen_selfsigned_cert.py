from cryptography.x509 import Name, NameOID, CertificateBuilder, SubjectAlternativeName, DNSName, NameAttribute
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import datetime

def create_self_signed_cert(in_domain):
  # Generate private key
  private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
  )

  # Generate public key
  public_key = private_key.public_key()

  # Create certificate builder
  subject = issuer = x500_name = Name([
    NameAttribute(NameOID.COUNTRY_NAME, 'US'),
    NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'California'),
    NameAttribute(NameOID.LOCALITY_NAME, 'San Francisco'),
    NameAttribute(NameOID.ORGANIZATION_NAME, 'Fake CA'),
    NameAttribute(NameOID.COMMON_NAME, in_domain),
  ])


  # We create a certificate from the mocked data above as issuer_name and subject_name
  # Using just '1' for serial number as this won't be used in any production whatsoever
  # Set expiration
  cert_builder = CertificateBuilder().subject_name(x500_name).issuer_name(x500_name).public_key(
    public_key).serial_number(1).not_valid_before(datetime.datetime.utcnow()).not_valid_after(
      datetime.datetime.utcnow() + datetime.timedelta(days=365)
  )

  # Add the subject alternative name (SAN) as the domain name that we spoof
  # Critical = False, again, this cert will only be used for stripping of connection and redirect to our http server
  cert_builder = cert_builder.add_extension(
    SubjectAlternativeName([DNSName(in_domain)]),
    critical=False
  )

  # Sign the certificate
  cert = cert_builder.sign(private_key, hashes.SHA256(), default_backend())

  # Save the certificate and private key to files
  cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
  key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
  )

  with open(f"cert.pem", "wb") as cert_file:
    cert_file.write(cert_pem)

  with open(f"key.pem", "wb") as key_file:
    key_file.write(key_pem)

  return cert_pem, key_pem