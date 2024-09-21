from socket import *
import socket
import sys

client_2_socket = socket.socket()

host = "127.0.0.1"
port = 9999

print("Waiting for connection...")

try:
  client_2_socket.connect((host, port))
except socket.error as error:
  print(str(error))

response = client_2_socket.recv(1024)
print(response.decode("utf-8"))

while True:
    user_input = input("Send a message to the server: ")
    client_2_socket.send(str.encode(user_input))
    response = client_2_socket.recv(1024)
    print(response.decode("utf-8"))

client_2_socket.close()