#! /usr/bin/env python3

import argparse
import socket
import shlex
import subprocess
import sys
import textwrap
import threading

#define global vars to identify connection
hostname = socket.gethostname().encode()

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

        #continuously read from socket and send user input
        try:
            running = True
            while True:
                response = ''
                while running:
                    self.socket.settimeout(10.0)
                    data = self.socket.recv(4096)
                    recv_len = len(data)
                    if recv_len == 0:
                        print("[-] Connection closed by remote host.")
                        break
                    chunk = data.decode()
                    response += chunk
                    print(chunk, end='', flush=True)
                    if recv_len < 4096:
                        break
                if self.args.target in response:
                    buffer = input(' ')
                    if buffer.lower() == 'exit' or buffer.lower() == 'quit':
                        print('Exiting.')
                        self.socket.close()
                        sys.exit()
                    buffer += '\n'
                    self.socket.send(buffer.encode())

        #quit on Ctrl-C, send exit message to remote host
        except KeyboardInterrupt:
            self.socket.send(b'exit\n')
            print('Exiting.')
            
        #handle unexpected errors
        except Exception as e:
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
                print(f'[+] Accepted connection from {client_socket.getpeername()[0]}:{client_socket.getpeername()[1]}')
                message = b'[+] Connection established.'
                client_socket.send(message)

                #pass client socket to handle function in new thread
                #daemon=True allows main program to exit even if threads are running
                
                client_thread = threading.Thread(
                    target=self.handle, args=(client_socket,)
                    )
                client_thread.daemon = True
                client_thread.start()
                

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
        
        #if upload requested, set loop to listen for content on listening socket and receive data until none left, then write to file
        elif self.args.upload:
            print(f'[*] Receiving content and saving to {self.args.upload}')
            file_buffer = b''
            while True:
                data = client_socket.recv(4096)
                if data:
                    file_buffer += data
                else:
                    break
            with open(self.args.upload, 'ab') as f:
                f.write(file_buffer)
            message = f'[+] Saved file {self.args.upload}'
            client_socket.send(message.encode())
            
        #if command shell requested, set loop to send prompt to sender, wait for command string, execute it, and send back results
        elif self.args.command:
            cmd_buffer = b''
            incoming = True
            while incoming == True:
                try:
                    client_socket.send(b'<' + hostname + b'@' + (self.args.target).encode() + b'#>')
                    while '\n' not in cmd_buffer.decode():
                        cmd_buffer += client_socket.recv(64)
                    print("[>] Received: " + cmd_buffer.decode())
                    if cmd_buffer.decode().lower().strip() == 'exit':
                        print('[x] Client disconnected.')
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

    #entry point for managing NetCat object
    def run(self):
        if self.args.listen:
            self.listen()
        elif self.args.upload and not self.args.listen:
            parser.error('-u/--upload requires -l/--listen')
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
            echo 'ABCDEFGHI' | ./netcat.py -t 192.168.1.100 -p 135 # echo text to server port 135
        '''))
    
    #define arguments
    parser.add_argument('-c', '--command', action='store_true', help='command shell')
    parser.add_argument('-e', '--execute', help='execute specified command')
    parser.add_argument('-l', '--listen', action='store_true', help='listen')
    parser.add_argument('-p', '--port', required=True, type=int, help='specified port')
    parser.add_argument('-t', '--target', required=True, help='specified IP')
    parser.add_argument('-u', '--upload', help='upload file')
    args = parser.parse_args()

    #set buffer to empty string, avoids IO issues
    buffer = b''
    nc = NetCat(args, buffer)
    nc.run()