from socket import *
import socket
import sys

udp_client_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
message="Hello UDP Server"
udp_client_socket.sendto(message.encode("utf-8"), ('127.0.0.1', 9999))

data,addr = udp_client_socket.recvfrom(4096)
print("Server Says")
print(str(data))

udp_client_socket.close()