import socket
import os

#TODO: Add automatic port scan for live hosts

#listener host
HOST = '192.168.1.9'

def main():
    #create raw socket, bind to public interface, check for OS specifics to set socket protocol
    if os.name == 'nt':
        # on Windows use IP protocol
        socket_protocol = socket.IPPROTO_IP
        # on Linux use ICMP protocol
    else:
        socket_protocol = socket.IPPROTO_ICMP
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((HOST, 0))
    #include IP headers in captured packets
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    #if on Windows, set promiscuous mode
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    #read in a single packet
    print(sniffer.recvfrom(65565))

    #if on Windows, turn off promiscuous mode
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

if __name__ == '__main__':
    main()
    
