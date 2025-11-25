#!/usr/bin/env python3

import sys
import socket
import threading

#1. display comms between local and remote machines to console

#printable chars indicated by len==3
#for each integer in range 0-255, if len==3, return the ASCII-printable character (i.e. 'a' --> a), otherwise return '.'
HEX_FILTER = ''.join([(len(repr(chr(i))) == 3) and chr(i) or '.' for i in range(256)])

#takes input as bytes or string and prints hexdump to console i.e., output packet details with both hexadecimal values and ASCII-printable chars
def hexdump(src, length=16, show=True):
    #decode if src==bytes
    if isinstance(src, bytes):
        src = src.decode()
    
    #array to hold strings, contains hex value of index of first bye in the word, hex value of word, printable representation
    results = list()

    #pass piece of src string to word variable
    for i in range(0, len(src), length):
        word = str(src[i:i+length])

        #use translate to sub string repr(esentation) of char to corresponding char in raw string
        printable = word.translate(HEX_FILTER)
        #sub hex representation of integer value of every character in raw string
        hexa = ' '.join([f'{ord(c):02X}' for c in word])
        hexwidth = length*3
        results.append(f'{i:04x} {hexa:<{hexwidth}} {printable}')
    if show:
        for line in results:
            print(line)
    else:
        return results

#2. receive data from incoming socket from either local or remote machine

def receive_from(connection):
    buffer = b""
    connection.settimeout(5)
    try:
        while True:
            #read response data until there is no more, timeout or other exception
            data = connection.recv(4096)
            if not data:
                break
        buffer += data
    except Exception as e:
        print("[-] Error occured: " + e)
        pass
    #return buffer byte string to caller
    return buffer

#3. manage traffic direction between remote and local machines

def request_handler(buffer):
    #modify request packets
    return buffer

def response_handler(buffer):
    #modify request packets
    return buffer

def proxy_handler(client_socket, remote_host, remote_port, receive_first):
    #connect to remote host
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect((remote_host, remote_port))

    #check if we need to initiate connection and request data such as a banner
    if receive_first:
        remote_buffer = receive_from(remote_socket)
        hexdump(remote_buffer)


    remote_buffer = response_handler(remote_buffer)
    if len(remote_buffer):
        print("[<==] Sending %d bytes to localhost." % len(remote_buffer))
        client_socket.send(remote_buffer)

    while True:
        local_buffer = receive_from(client_socket)
        if len(local_buffer):
            line = "[==>]Received %d bytes from localhost." % len(local_buffer)
            print(line)
            hexdump(local_buffer)
            print("[==>] Sent to remote.")

        remote_buffer = receive_from(remote_socket)
        if len(remote_buffer):
            print("[<==] Received %d bytes from remote." % len(remote_buffer))
            hexdump(remote_buffer)

            remote_buffer = response_handler(remote_buffer)
            client_socket.send(remote_buffer)
            print("[<==] Sent to localhost.")

        if not len(local_buffer) or not len(remote_buffer):
            client_socket.close()
            remote_socket.close()
            print("[-] No more data. Closing connection.")
            break
#4. set up listening socket and pass to proxy_handler

# hexdump()