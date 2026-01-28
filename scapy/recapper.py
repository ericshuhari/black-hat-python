from scapy.all import TCP, rdpcap
import collections
import os
import re
import sys
import zlib

OUTDIR = '/root/Desktop/pictures'
PCAPS = '/root/Desktop/pcaps'

# named tuple to hold response header and payload
Response = collections.namedtuple('Response', ['header', 'payload'])

# extract packet header
def get_header(payload):
    try:
        header_raw = payload[:payload.index(b'\r\n\r\n')+2]
    except ValueError:
        sys.stdout.write('-')
        sys.stdout.flush()
        return None

    header = dict(re.findall(r'(?P<name>.*?): (?P<value>.*?)\r\n', header_raw.decode()))
    if 'Content-Type' not in header:
        return None
    return header

# extract packet contents
def extract_content(Response, content_name='image'):
    pass

class Recapper:
    def __init__(self, fnmae):
        pass

    # read responses from pcap file
    def get_responses(self):
        pass

    # write extracted contents (images) to files
    def write(self, content_name):
        pass

if __name__ == '__main__':
    pfile = os.path.join(PCAPS, 'pcap.pcap')
    recapper = Recapper(pfile)
    recapper.get_responses()
    recapper.write('image')
