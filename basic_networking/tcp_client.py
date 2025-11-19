import socket

target_host = "127.0.0.1"
target_port = 9998

#create a socket object
#AF_INET refers to the address family ipv4
#SOCK_STREAM means connection oriented TCP protocol

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#connect the client
client.connect((target_host, target_port))

#send some data as bytes
client.send(b"GET / HTTP/1.1\r\nHost: google.com\r\n\r\n")

#receive some data
response = client.recv(4096)

#display the response
print(response.decode())

#close the client
client.close()