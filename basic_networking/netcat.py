#! /usr/bin/env python3

import argparse
import socket
import shlex
import subprocess
import sys
import textwrap
import threading

#handle command execution
def execute(cmd):
    cmd = cmd.strip()
    if not cmd:
        #empty string return to avoid errors in handle function
        return #str()
    
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
        # self.socket.send(b'\x04') # EOT to prevent EOFError on server side
        
        #send buffer data if exists
        if self.buffer:
            self.socket.send(self.buffer)
            self.socket.shutdown(socket.SHUT_WR) # close the writing side of the socket, remote recv() will get EOF


        #continuously read from socket and send user input
        try:
            while True:
                recv_len = 1
                response = ''
                while recv_len:
                    data = self.socket.recv(4096)
                    if data == b'':
                        print('eof')
                        break
                    recv_len = len(data)
                    response += data.decode()
                    if recv_len < 4096:
                        print("break")
                        break
                if response:
                    print(response)
                    # buffer = input('> ')
                    #Copilot suggestion to allow multi-line input until an empty line is entered
                    input_lines = []
                    while True:
                        try:
                            line = input('> ')
                        except EOFError:
                            print('EOF received, exiting.')
                            self.socket.close()
                            return
                        if line == '':
                            break
                        input_lines.append(line)
                    # buffer += '\n'
                    # self.socket.send(buffer.encode())
                #     try:
                #         buffer = input('> ')
                #         buffer += '\n'
                #         self.socket.send(buffer.encode())
                #     except EOFError:
                #         print('EOF received, exiting.')
                #         self.socket.close()
                #         return
                    
                    

        except KeyboardInterrupt:
            print('User terminated.')
            self.socket.close()
            sys.exit()

    def listen(self):

        #bind and listen on target host and port
        self.socket.bind((self.args.target, self.args.port))
        self.socket.listen(5)
        print(f'[*] Listening on {self.args.target}:{self.args.port}')

        #constantly accept incoming connections
        while True:
            client_socket, _ = self.socket.accept()
            #sending this back to the client prevents EOF error on client side
            print(f'[+] Accepted connection from {client_socket.getpeername()[0]}:{client_socket.getpeername()[1]}')
            # self.socket.send(b'\x04') 
            # self.socket.shutdown(socket.SHUT_WR) # close the writing side of the socket, remote recv() will get EOF

            #pass client socket to handle function in new thread
            client_thread = threading.Thread(
                target=self.handle, args=(client_socket,)
                )
            client_thread.start()

    def handle(self, client_socket):
        #if command execution requested, pass command to execute function and sned output back on the socket
        if self.args.execute:
            output = execute(self.args.execute)
            client_socket.send(output.encode())
            # client_socket.send(str(output).encode())
        
        #if upload requested, set loop to listen for content on listening socket and receive data until none left, then write to file
        elif self.args.upload:
            print(f'[*] Receiving content and saving to {self.args.upload}')
            file_buffer = b''
            while True:
                data = client_socket.recv(4096)
                if data:
                    file_buffer += data
                    # with open(self.args.upload, 'wb') as f:
                    #     f.write(file_buffer)
                    # message = f'Saved file {self.args.upload}'
                    # client_socket.send(message.encode())
                else:
                    break
            with open(self.args.upload, 'ab') as f:
                f.write(file_buffer)
            message = f'Saved file {self.args.upload}'
            client_socket.send(message.encode())
            # client_socket.shutdown(socket.SHUT_WR) # close the writing side of the socket, remote recv() will get EOF
           
            # cmd_buffer = b''
            # while True:
            #     try:
            #         client_socket.send(b'BHP: #> ')
            #         while '\n' not in cmd_buffer.decode():
            #             cmd_buffer += client_socket.recv(64)
            #         response = execute(cmd_buffer.decode())
            #         if response:
            #             client_socket.send(response.encode())
            #         cmd_buffer = b''
            #     except Exception as e:
            #         print(f'Server killed {e}')
            #         self.socket.close()
            #         sys.exit()
        
        #if command shell requested, set loop to send prompt to sender, wait for command string, execute it, and send back results
        elif self.args.command:
            cmd_buffer = b''
            while True:
                try:
                    client_socket.send(b'BHP: #> ')
                    while '\n' not in cmd_buffer.decode():
                        cmd_buffer += client_socket.recv(64)
                    response = execute(cmd_buffer.decode())
                    if response:
                        client_socket.send(response.encode())
                    cmd_buffer = b''
                except Exception as e:
                    print(f'Server killed {e}')
                    self.socket.close()
                    sys.exit()



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
    parser.add_argument('-p', '--port', type=int, default=5555, help='specified port')
    parser.add_argument('-t', '--target', default='192.168.129.128', help='specified IP')
    parser.add_argument('-u', '--upload', help='upload file')
    args = parser.parse_args()

    #read from stdin if not listening, otherwise set buffer to empty string
    if args.listen:
        buffer = ''
    else:
        buffer = sys.stdin.read()
    nc = NetCat(args, buffer.encode())
    nc.run()