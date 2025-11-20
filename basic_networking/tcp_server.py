#! /usr/bin/env python3

import socket
import threading

IP = '0.0.0.0'
PORT = 9998

def main():
    #create a socket object
    #AF_INET refers to the address family ipv4
    #SOCK_STREAM means connection oriented TCP protocol
    #max backlog of connections set to 5

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((IP, PORT))
    server.listen(5)
    print(f'[*] Listening on {IP}:{PORT}')

    #handle incoming connections
    #threading to handle multiple clients

    while True:
        client, address = server.accept()
        print(f'[*] Accepted connection from {address[0]}:{address[1]}')
        client_handler = threading.Thread(target=handle_client, args=(client,))
        client_handler.start()

#function to handle client connections
#receives data and sends an acknowledgment

def handle_client(client_socket):
    with client_socket as sock:
        request = sock.recv(1024)
        print(f'[*] Received: {request.decode("utf-8")}')
        sock.send(b'ACK')
            
if __name__ == '__main__':
    main()