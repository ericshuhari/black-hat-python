#! /usr/bin/env python3

import argparse
import socket
import shlex
import subprocess
import sys
import textwrap
import threading
import datetime

#define global vars to identify connection
hostname = socket.gethostname().encode()
disconnect = b'exit\n'

#handle command execution
def execute(cmd):
    cmd = cmd.strip()
    if not cmd:
        #empty string return to avoid errors in handle function
        return
    
    #run the command and get the output
    output = subprocess.check_output(shlex.split(cmd),
                                     stderr=subprocess.STDOUT)
    return output.decode()

class NetCat:
    #initialze NetCat object with CLI args and optional buffer
    def __init__ (self, args, buffer=None):
        self.args = args
        self.buffer = buffer

        #create socket object
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        #SOL_SOCKET set a generic socket level option
        #SO_REUSEADDR, 1 allow socket to bind to address in TIME_WAIT state or otherwise marked as in use
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    def send(self):

        #connect to target host and port
        self.socket.connect((self.args.target, self.args.port))
        
        #receive initial banner to avoid I/O blocking
        banner = self.socket.recv(4096)
        if banner:
            print(banner.decode())

        #send buffer data if exists
        if self.buffer:
            self.socket.send(self.buffer)
            self.socket.shutdown(socket.SHUT_WR)
            self.socket.recv(4096)
            # sys.exit()

        #continuously read from socket and send user input
        try:
            running = True
            buffer = ''
            
            while True:
                
                response = ''
                while running:
                    self.socket.settimeout(3.0)
                    #handle socket timeout to allow KeyboardInterrupt
                    try:
                        data = self.socket.recv(4096)
                    except socket.timeout:
                        print("Socket timeout. Press Ctrl+C to exit.")
                        continue
                    recv_len = len(data)
                    if recv_len == 0:
                        print("[-] Connection closed by remote host.")
                        return
                    chunk = data.decode()
                    response += chunk
                    print(chunk, end='', flush=True)
                    if recv_len < 4096:
                        break
                if self.args.target in response:
                    #additional control of command shell, allow typing exit/quit to close shell.
                    buffer = input(' ')
                    if 'exit' in buffer.lower() or 'quit' in buffer.lower():
                        end = input("Exit command shell? (y)es/(n)o: ")
                        s = end.strip().lower()
                        if (not s or s[0] not in ("y","n")) or s[0] == "n":
                            print(chunk, end='', flush=True)
                            buffer = input(' ')
                            if buffer.strip().lower() in ("exit","quit"):
                                self.socket.send(disconnect)
                                print('Exiting.')
                                sys.exit()
                        elif s[0] == "y":
                            buffer = 'exit\n'
                            self.socket.send(disconnect)
                            print('Exiting.')
                            sys.exit()
                    buffer += '\n'
                    self.socket.send(buffer.encode())
                buffer = ''

        #quit on Ctrl-C
        except KeyboardInterrupt:
            self.socket.send(disconnect)
            print('Exiting.')
            
        #handle unexpected errors
        except Exception as e:
            self.socket.send(disconnect)
            print(f'[-] Error occurred: {e}')
        self.socket.close()
        sys.exit()

    def listen(self):

        #bind and listen on target host and port
        self.socket.bind((self.args.target, self.args.port))
        self.socket.listen(5)
        print(f'[*] Listening on {self.args.target}:{self.args.port}')

        #constantly accept incoming connections
        while True:
            try:
                client_socket, _ = self.socket.accept()
                connect_time = datetime.datetime.now()
                print(f'[+] Accepted connection from {client_socket.getpeername()[0]}:{client_socket.getpeername()[1]} at {connect_time}')
                message = f'[+] Connection established at {connect_time}.'
                client_socket.send(message.encode())

                #pass client socket to handle function in new thread
                #daemon=True allows main program to exit even if threads are running
                
                client_thread = threading.Thread(
                    target=self.handle, args=(client_socket,)
                    )
                client_thread.daemon = True
                client_thread.start()
                
            #listener error handling
            except KeyboardInterrupt:
                print('Exiting.')
                sys.exit()
            except(BrokenPipeError,ConnectionResetError,OSError) as e:
                client_socket.send(b'[-] Connection error. Closing socket.\n')
                print(f'Connection error: {e}')
                self.socket.close()
                sys.exit()

    def handle(self, client_socket):
        #if command execution requested, pass command to execute function and sned output back on the socket
        if self.args.execute:
            output = execute(self.args.execute)
            client_socket.send(output.encode())
            client_socket.shutdown(socket.SHUT_WR)
        
        #if upload requested, set loop to listen for content on listening socket and receive data until none left, then write to file
        elif self.args.upload:
            try:
                print(f'[*] Receiving content and saving to {self.args.upload}')
                file_buffer = b''
                while True:
                    data = client_socket.recv(4096)
                    data_len = len(file_buffer)
                    if data:
                        file_buffer += data
                    else:
                        #send and empty byte to break loop and inform sender we're done
                        client_socket.send(b' ')
                        break
                with open(self.args.upload, 'ab') as f:
                    f.write(file_buffer)
                message = f'[+] Saved file {self.args.upload}.\n[~] Sent {data_len} bytes. Goodbye!\n'
                client_socket.send(message.encode())            
                client_socket.close()
            except Exception as e:
                print(f"[-] Error occured: {e}")
            
        #if command shell requested, set loop to send prompt to sender, wait for command string, execute it, and send back results
        elif self.args.command:
            cmd_buffer = b''
            incoming = True
            while incoming == True:
                try:
                    client_socket.send(b'<' + hostname + b'@' + (self.args.target).encode() + b'#>')
                    while '\n' not in cmd_buffer.decode():
                        cmd_buffer += client_socket.recv(64)
                    print("[>] Received: " + cmd_buffer.decode().strip())
                    if cmd_buffer.decode().lower().strip() == 'exit':
                        print('[x] Agent disconnected.')
                        sys.exit()
                    response = execute(cmd_buffer.decode())
                    if response:
                        client_socket.send(b'[+] ' + response.encode())
                    cmd_buffer = b''

                #error handling for connection issues, clears buffer to continue sending commands
                except Exception as e:
                    error_message = f'{e}'
                    print('[-] Error ocurred: ' + error_message)
                    client_socket.send(b'[-] Error executing command. ' + error_message.encode() + b'\n')
                    cmd_buffer = b''

    #entry point for managing NetCat object. sets various requirements for different arguments
    def run(self):
        if self.args.listen:
            self.listen()
        elif self.args.upload and not self.args.listen:
            parser.error('-u/--upload requires -l/--listen')
        elif self.args.execute and not self.args.listen:
            parser.error('-e/--execute requires -l/--listen')
        elif self.args.command and not self.args.listen:
            parser.error('-c/--command requires -l/--listen')
        elif self.args.upload and (self.args.execute or self.args.command):
            parser.error('-u/--upload cannot be used with -e/--execute or -c/--command')
        elif self.args.execute and self.args.command:
            parser.error('-e/--execute cannot be used with -c/--command')
        else:
            self.send()

        
if __name__ == '__main__':

    #create CLI interface 
    parser = argparse.ArgumentParser(
        description='BHP Net Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,

        #display help message with examples
        epilog=textwrap.dedent('''Example:
            netcat.py -t 192.168.129.128 -p 5555 -l -c # command shell
            netcat.py -t 192.168.129.128 -p 5555 -l -u=mytest.txt # upload to file
            netcat.py -t 192.168.129.128 -p 5555 -l -e=\"cat /etc/passwd\" # execute command
            echo 'ABCDEFGHI' | ./netcat.py -t 192.168.1.100 -p 135 -s # echo text to server port 135
        '''))
    
    #define arguments
    parser.add_argument('-c', '--command', action='store_true', help='command shell')
    parser.add_argument('-e', '--execute', help='execute specified command')
    parser.add_argument('-l', '--listen', action='store_true', help='listen')
    parser.add_argument('-p', '--port', required=True, type=int, help='specified port')
    parser.add_argument('-t', '--target', required=True, help='specified IP')
    parser.add_argument('-u', '--upload', help='upload file')
    parser.add_argument('-s', '--send', action='store_true', help='send data by pipe')
    args = parser.parse_args()

    if args.send:
        buffer = sys.stdin.read().encode()
    else:
        #if data is being piped to the script for uploading to a remote file, i.e. sys.stdin is NOT interactive, --send argument required to ensure the send buffer is populated with the contents
        if not sys.stdin.isatty():
             parser.error('piped data requires -s/--send')
        buffer = ''

    nc = NetCat(args, buffer)
    nc.run()