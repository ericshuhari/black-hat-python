import socket
import os
from ctypes import *
import ipaddress
import struct
import sys
import threading
import time

# target subnet
SUBNET = '192.168.1.0/24'
# magic string to check ICMP responses for
MESSAGE = 'PYTHONRULES!'

class IP(Structure):
    _fields = [
        ("ihl", c_ubyte, 4), # 4 bit unsigned char
        ("version", c_ubyte, 4), # 4 bit unsigned char
        ("tos", c_ubyte), # 1 byte char
        ("len", c_ushort), # 2 byte unsigned short
        ("id", c_ushort),  # 2 byte unsigned short
        ("offset", c_ushort), # 2 byte unsigned short
        ("ttl", c_ubyte), # 1 byte char
        ("protocol_num", c_ubyte), # 1 byte char
        ("sum", c_ushort), # 2 byte unsigned short
        ("src", c_uint32), # 4 byte unsigned int
        ("dst", c_uint32)  # 4 byte unsigned int
    ]
# map first 20 bytes of a buffer into IP structure
class IP:
    def __init__(self, buff=None):
        # first format character, <, specifies little-endian byte order, least significant byte in lowest address, most significant byte in highest address
        # next format charactesr represent individual fields of the IP header, B for unsigned char (1 byte), H for unsigned short (2 bytes), 4s for 4 byte string (s)
        header = struct.unpack('<BBHHHBBH4s4s', buff)
        # assign high-order (first) nybble in byte to version, second nybble to IHL
        # bitwise right shift operator (>>), shifts bits to the right by prepending specified number (4) of 0s
        self.ver = header[0] >> 4
        # assign low-order (second) nybble in byte to IHL
        # bitwise AND operator (&), compares each bit of two operands and returns 1 if both bits are 1, otherwise returns 0
        self.ihl = header[0] & 0xF
        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = ipaddress.ip_address(header[8])
        self.dst = ipaddress.ip_address(header[9])

    # continuously read and parse packets
    # human readable IP addresses
        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

        # map protocol constants to their names
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as e:
            print('%s No protocol for %s' % (e, self.protocol_num))
            self.protocol = str(self.protocol_num)

# ICMP packet structure
class ICMP:
    def __init__(self, buff):
        header = struct.unpack('<BBHHH', buff)
        self.type = header[0]
        self.code = header[1]
        self.checksum = header[2]
        self.id = header[3]
        self.seq = header[4]

# TODO: Add automatic port scan for live hosts

# spray UDP datagarams with magic message
def udp_sender():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        for ip in ipaddress.ip_network(SUBNET).hosts():
            sender.sendto(bytes(MESSAGE,'utf8'), (str(ip), 65212))

class Scanner:
    def __init__(self,host):
        self.host = host
        if os.name =='nt':
            socket_protocol = socket.IPPROTO_IP
        else:
            socket_protocol = socket.IPPROTO_ICMP
        
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

        self.socket.bind((host, 0))

        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        if os.name == 'nt':
            self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)


    def sniff(self):
        hosts_up = set([f'{str(self.host)} *'])
        # if os.name == 'nt':
        #     socket_protocol = socket.IPPROTO_IP
        # else:
        #     socket_protocol = socket.IPPROTO_ICMP

        # sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        # sniffer.bind((host, 0))
        # sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # if os.name == 'nt':
        #     sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        try:
            while True:
                #read in a single packet
                raw_buffer = self.socket.recvfrom(65565)[0]
                #create an IP header from the first 20 bytes of the buffer
                ip_header = IP(raw_buffer[0:20])
                # if the protocol is ICMP, analyze packet further
                if ip_header.protocol == "ICMP":
                    # print out the protocol and the hosts
                    print("Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address))
                    print(f'Version: {ip_header.ver}')
                    print(f'Header Length: {ip_header.ihl} TTL: {ip_header.ttl}')
                    #calculate where our ICMP packet starts
                    offset = ip_header.ihl * 4
                    buf = raw_buffer[offset:offset + 8]
                    # create ICMP structure
                    icmp_header = ICMP(buf)
                    #check for the TYPE 3 and CODE 3 which indicates "Destination Unreachable" and "Port Unreachable"
                    if icmp_header.type == 3 and icmp_header.code == 3:
                        #check to make sure we are receiving packets from within our subnet
                        if ipaddress.ip_address(ip_header.src_address) in ipaddress.ip_network(SUBNET):
                            #check for our magic message
                            if raw_buffer[len(raw_buffer)-len(MESSAGE):] == bytes(MESSAGE,'utf8'):
                                tgt = str(ip_header.src_address)
                                if tgt != self.host and tgt not in hosts_up:
                                    hosts_up.add(str(ip_header.src_address))
                                    print(f'Host Up: {tgt}')
                    # print('ICMP -> Type: %s Code: %s' % (icmp_header.type, icmp_header.code))

        except KeyboardInterrupt:
            #if on Windows, turn off promiscuous mode
            if os.name == 'nt':
                sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            print('\nUser interrupted.')
            if hosts_up:
                print(f'\n\nSummary: Hosts up on {SUBNET}')
            for hosts in sorted(hosts_up):
                print(f'{hosts}')
            print('')
            sys.exit()

if __name__ == '__main__':
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = '192.168.1.15'
    s = Scanner(host)
    t = threading.Thread(target=udp_sender)
    t.start()
    s.sniff()