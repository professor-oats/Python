from socket import *
import socket
import sys

tcp_server_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
tcp_server_socket.bind(('127.0.0.1', 9999))
tcp_server_socket.listen(5)

while True:
  print("Server waiting for connection")
  tcp_client_socket, address = tcp_server_socket.accept()
  print("Client connected from: " + str(address))
  while True:
    data=tcp_client_socket.recv(1024)
    if not data or data.decode('utf-8') == 'END':
      break

    print("Received from client client: %s"% data.decode('utf-8'))

    try:
      tcp_client_socket.send(bytes("Hey client", "utf-8"))
    except:
      print("Exited by user")

  tcp_client_socket.close()

## Fix this outside of while true scope
tcp_server_socket.close()