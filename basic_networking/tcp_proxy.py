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
    
    #array to hold strings, contains hex value of offset of first byte in the chunk, hex value of chars, printable representation
    results = list()

    #pass piece of src string to word variable
    for i in range(0, len(src), length):
        word = str(src[i:i+length])

        #use translate to sub string repr(esentation) of char to corresponding char in raw string
        printable = word.translate(HEX_FILTER)
        #sub hex representation of integer value of every character in raw string
        hexa = ' '.join([f'{ord(c):02X}' for c in word])
        hexwidth = length*3
        #output formatted string to results array: byte offset within data stream, hex representation, printable representation
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
    except (Exception,KeyboardInterrupt) as e:
        print("[-] Error occured: " + e)
        pass
    #return buffer byte string to caller
    return buffer

#3. manage traffic direction between remote and local machines

def request_handler(buffer):
    #modify request packets
    return buffer

def response_handler(buffer):
    #modify response packets
    return buffer

def proxy_handler(client_socket, remote_host, remote_port, receive_first):
    #connect to remote host
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect((remote_host, remote_port))
    remote_socket.settimeout(5)

    #check if we need to initiate connection and request data such as a banner, dump to console
    if receive_first:
        remote_buffer = receive_from(remote_socket)
        hexdump(remote_buffer)

    #pass response to local handler
    remote_buffer = response_handler(remote_buffer)
    if len(remote_buffer):
        print("[<==] Sending %d bytes to localhost." % len(remote_buffer))
        client_socket.send(remote_buffer)

    #facilitate continuous bi-directional comms between local and remote hosts
    while True:
        #receive remote data from client_socket, populate local_buffer, dump to console
        local_buffer = receive_from(client_socket)
        if len(local_buffer):
            line = "[==>]Received %d bytes from localhost." % len(local_buffer)
            print(line)
            hexdump(local_buffer)

            #send local_buffer to remote host
            local_buffer = request_handler(local_buffer)
            remote_socket.send(local_buffer)
            print("[==>] Sent to remote.")

        #pass data from remote host to local host
        remote_buffer = receive_from(remote_socket)
        if len(remote_buffer):
            print("[<==] Received %d bytes from remote." % len(remote_buffer))
            hexdump(remote_buffer)

            remote_buffer = response_handler(remote_buffer)
            client_socket.send(remote_buffer)
            print("[<==] Sent to localhost.")

        #if no more data on either side, close connections
        if not len(local_buffer) or not len(remote_buffer):
            client_socket.close()
            remote_socket.close()
            print("[-] No more data. Closing connection.")
            break

#4. set up listening socket and pass to proxy_handler
def server_loop(local_host, local_port, 
                remote_host, remote_port, receive_first):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((local_host, local_port))
    except (Exception) as e:
        print('[-] Problem on bind: %r' % e)

        print("[!] Failed to listen on %s:%d" % (local_host, local_port))
        print("[!] Check for other listening sockets or correct permissions.")
        print("Exception: " + str(e))
        sys.exit(0)
    
    print("[*] Listening on %s:%d" % (local_host, local_port))
    try:
        server.listen(5)
    except KeyboardInterrupt:
        print("\n[*] User requested an interrupt.")
        print("[*] Exiting...")
        server.close()
        sys.exit()
    while True:
        try:
            client_socket, addr = server.accept()
            print("[==>] Received incoming connection from %s:%d" % (addr[0], addr[1]))

            #start a thread to talk to the remote host
            proxy_thread = threading.Thread(target=proxy_handler, args=(client_socket, remote_host, remote_port, receive_first))
            proxy_thread.daemon = True
            proxy_thread.start()
        except KeyboardInterrupt:
            print("\n[*] User requested an interrupt.")
            print("[*] Exiting...")
            server.close()
            sys.exit()
def main():
    if len(sys.argv[1:]) != 5:
        print("Usage: ./tcp_proxy.py [localhost] [localport]", end='')
        print(" [remotehost] [remoteport] [receive_first]")
        print("Example: ./tcp_proxy.py 127.0.0.1 9000 10.12.132.1 9000 True")
        sys.exit(0)

    local__host = sys.argv[1]
    local_port = int(sys.argv[2])
    remote_host = sys.argv[3]
    remote_port = int(sys.argv[4])
    receive_first = sys.argv[5] 

    if "True" in receive_first:
        receive_first = True
    else:
        receive_first = False
    
    server_loop(local__host, local_port, remote_host, remote_port, receive_first)
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] User requested an interrupt.")
        print("[*] Exiting...")
        sys.exit()
# hexdump()