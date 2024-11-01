import http.server
import socketserver
import os

class MyHttpRequestHandler(http.server.SimpleHTTPRequestHandler):
  def end_headers(self):
    self.send_header('Access-Control-Allow-Origin', '*')
    super().end_headers()

def run_fileserver(serve_path, port):
  os.chdir(serve_path)
  handler_object = MyHttpRequestHandler

  with socketserver.TCPServer(("", port), handler_object) as httpd:
    print(f'Serving {serve_path} at port {port}')
    print("Server is running. Press Ctrl+C to stop the server.")

    try:
      httpd.serve_forever()
    except KeyboardInterrupt:
      pass

    print("Server stopped.")
    httpd.server_close()
    print("Server closed.")

    return

def main():
  PORT = 9999
  while True:
    SERVE_PATH = input("Enter the path you want to serve (leave empty for cwd):\n")
    if not SERVE_PATH:
      SERVE_PATH = os.getcwd()
    if os.path.exists(SERVE_PATH):
      break
    else:
      print("Path does not exist. Make sure path exists")

  run_fileserver(SERVE_PATH, PORT)

if __name__ == '__main__':
  main()


