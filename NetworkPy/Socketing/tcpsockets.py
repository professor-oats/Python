from socket import *
import socket
import sys


try:
  tcp_client_socket=socket.socket(family=AF_INET, type=SOCK_STREAM)
except socket.error as error:
  print("Failed to create socket")
  print("Reason: " + str(error))
  sys.exit()

print("TCP client socket created successfully")

target_host = input("Enter the target host to connect: ")
target_port = input("Enter the target port: ")

try:
  tcp_client_socket.connect((target_host, int(target_port)))
  print(f'Socket connected to {target_host}:{target_port}')
  tcp_client_socket.shutdown(2)
except socket.error as error:
  print("Failed to connect to server")
  print("Reason: " + str(error))
  sys.exit()

  



