#!/usr/bin/env python3
 
import socket

target_host = input(" Enter an IP address")
target_port = int(input(" Enter a port number"))

 #create a socket object

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

 #connect the client

client.connect((target_host, target_port))

 #send some data
client.send(f"GET / HTTPS/1.1\r\nHost: {target_host}\r\n\r\n".encode)
#receive some data

response = client.recv(4096)

print(response.decode)

client.close


