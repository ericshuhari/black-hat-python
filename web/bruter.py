import queue
import requests
import threading
import sys

AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
EXTENSIONS = [".php", ".bak", ".orig", ".inc"]
TARGET = "http://192.168.127.128/forums"
THREADS = 5
WORDLIST = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
answers = queue.Queue()

# queue for files to test on target
def get_words(resume=None):

    # append both the word and the word with each extension to the words queue, handling both file and directory paths
    def extend_words(word):
        if "." in word:
            words.put(f'/{word}')
        else:
            words.put(f'/{word}/')

        for extension in EXTENSIONS:
            words.put(f'/{word}{extension}')

    with open(WORDLIST) as f:
        # read the entire wordlist into memory
        raw_words = f.read()
        
    found_resume = False
    words = queue.Queue()
    for word in raw_words.split():
        # set resume to last attempted path, handles unexpected interruptions in the brute-force process
        if resume is not None:
            if found_resume:
                extend_words(word)
            elif word == resume:
                found_resume = True
                print(f'Resuming wordlist from: {resume}')
        else:
            print(word)
            extend_words(word)
    # return the queue containing all the words to be tested
    return words

def dir_bruter(words):
    # set a custom User-Agent header to mimic a real browser 
    headers = {'User-Agent': AGENT}
    
    while not words.empty():
        # loop through words queue and contstruct URLs to test on the target
        url = f'{TARGET}{words.get()}'
        try:
            r = requests.get(url, headers=headers)
        # handle connection errors gracefully
        except requests.exceptions.ConnectionError:
            sys.stderr.write('x');sys.stderr.flush()
            continue
        # TODO: handle with a queue
        if r.status_code == 200:
            answers.put(url)
            print(f'\nSuccess! ({r.status_code}): {url}')
        elif r.status_code == 404:
            sys.stderr.write('.');sys.stderr.flush()
        else:
            print(f'{r.status_code} => {url}')

if __name__ == "__main__":
    # get the words to test from the wordlist
    words = get_words()
    print('Press return to continue.')
    sys.stdin.readline()
    for _ in range(THREADS):
        t = threading.Thread(target=dir_bruter, args=(words,))
        t.start()
    with open(os.path.expanduser('~/Documents/bruter.txt'), 'w') as f:
        while not answers.empty():
            f.write(answers.get() + '\n')
    print(f'\nDone! Results saved in {os.path.expanduser("~/Documents/bruter.txt")}')