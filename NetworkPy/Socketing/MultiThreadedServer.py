import sys
from _thread import *
from socket import *
import socket

serversocket = socket.socket()

host = "127.0.0.1"
port = 9999
threadcount = 0

try:
  serversocket.bind((host, port))
except socket.error as error:
  print(str(error))
  sys.exit()

print("Waiting for connections...")
serversocket.listen(5)

def client_thread(conn):
  conn.send(str.encode("Welcome to the server"))
  while True:
    data = conn.recv(2048)
    reply = "Hello I am server: "+ data.decode("utf-8")

    if not data:
      break

    conn.sendall(reply.encode("utf-8"))
  conn.close()


while True:
  client,addr = serversocket.accept()
  print("Connected to " + addr[0] + " " + str(addr[1]))
  start_new_thread(client_thread,(client,))
  threadcount = threadcount + 1
  print("Threadnumber= " + str(threadcount))

serversocket.close()