from socket import *
import socket
import sys

tcp_client_socket=socket.socket(family=AF_INET, type=SOCK_STREAM)
tcp_client_socket.connect(("127.0.0.1", 9999))

payload='Hey Server'

try:
  while True:
    tcp_client_socket.send(payload.encode('utf-8'))
    data=tcp_client_socket.recv(1024)
    print(str(data))
    more=input("Want to send more data to the server? Y/N")
    if more.lower=="y":
      payload=input("Enter payload: ")
    else:
      break

except KeyboardInterrupt:
  print("Exited by user")
  tcp_client_socket.close()

