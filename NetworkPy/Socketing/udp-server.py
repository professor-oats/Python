from socket import *
import socket
import sys

udp_server_socket=socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
udp_server_socket.bind(('127.0.0.1',9999))

while True:
  ## For UDP we also need to have addr to have the server know
  ## where to send back data since UDP is connectionless
  ## client addr is received from the socket bind
  data,addr=udp_server_socket.recvfrom(4096)
  message=bytes("Hello I am UDP Server", encoding='utf-8')
  udp_server_socket.sendto(message,addr)