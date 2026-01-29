from scapy.all import TCP, rdpcap
import collections
import os
import re
import sys
import zlib

OUTDIR = '/home/majora/Desktop/pictures'
PCAPS = '/home/majora/Desktop/pcaps'

# named tuple to hold response header and payload
Response = collections.namedtuple('Response', ['header', 'payload'])

# extract packet header from raw HTTP traffic
def get_header(payload):
    try:
        print("[DEBUG] Attempting to extract header from payload.")
        print(f"[DEBUG] Payload preview: {payload.decode()}")
        # extract header by finding the new line sequence that indicates the end of the header
        header_raw = payload[:payload.index(b'\r\n\r\n')+2]
    except ValueError:
        # if header not found, indicate with a dash
        sys.stdout.write('-')
        sys.stdout.flush()
        return None

    # use regex to find all header fields and store them in a dictionary
    header = dict(re.findall(r'(?P<name>.*?): (?P<value>.*?)\r\n', header_raw.decode()))
    # return None if 'Content-Type' is not in header
    if 'Content-Type' not in header:
        # print("[DEBUG] 'Content-Type' not found in header.")
        return None
    # print(f"[DEBUG] Extracted headers: {header}")
    return header

# extract packet contents
def extract_content(Response, content_name='image'):
    content, content_type = None, None
    # responses containing an image contain 'image' in 'Content-Type' atrtribute (i.e. image/png, image/jpeg)
    if content_name in Response.header['Content-Type']:
        # get content type (e.g. png, jpeg)
        content_type = Response.header['Content-Type'].split('/')[1]
        # hold content, everything in payload after header
        content = Response.payload[Response.payload.index(b'\r\n\r\n')+4:]

        # decompress content if encoded
        if 'Content-Encoding' in Response.header:
            if Response.header['Content-Encoding'] == 'gzip':
                content = zlib.decompress(Response.payload, zlib.MAX_WBITS | 32)
            elif Response.header['Content-Encoding'] == 'deflate':
                content = zlib.decompress(Response.payload)

    return content, content_type
class Recapper:
    # initialize object with name of pcap file to read
    def __init__(self, fname):
        pcap = rdpcap(fname)
        # separate TCP sessions into dictionary containing each TCP stream
        self.sessions = pcap.sessions()
        # list to hold extracted responses from pcap file
        self.responses = list()

    # read responses from pcap file
    def get_responses(self):
        # iterate through each TCP session
        for session in self.sessions:
            payload = b''
            # iterate through each packet in the session
            for packet in self.sessions[session]:
                try:
                    # filter for packets with source or destination port 80 (HTTP)
                    # follow TCP stream in Wireshark
                    if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                        payload += bytes(packet[TCP].payload)
                except IndexError:
                    sys.stdout.write('x')
                    sys.stdout.flush()
            if payload:
                # pass payload to get_header function if not empty
                header = get_header(payload)
                if header is None:
                    continue
                # print(f"[DEBUG] Found response with Content-Type: {header.get('Content-Type')}")
                self.responses.append(Response(header=header,payload=payload))


    # write extracted contents (images) to files
    def write(self, content_name):
        # iterate over responses and extract content, write to file
        for i, response in enumerate(self.responses):
            content, content_type = extract_content(response, content_name)
            if content and content_type:
                fname = os.path.join(OUTDIR, f'ex_{i}.{content_type}')
                print(f'[+] Writing {fname}')
                with open(fname, 'wb') as f:
                    f.write(content)

if __name__ == '__main__':
    pfile = os.path.join(PCAPS, sys.argv[1])
    recapper = Recapper(pfile)
    recapper.get_responses()
    recapper.write('image')
