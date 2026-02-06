import contextlib
import os
import queue
import requests
import sys
import threading
import time

# Filter out files we don't care about
FILTERED = [".jpg", ".gif", ".png", ".css"]
TARGET = "http://192.168.129.129/wordpress"
THREADS = 10

# queue for located files
answers = queue.Queue()
# queue for paths to spider
web_paths = queue.Queue()

# Walk the current directory and subdirectories, adding all paths to the web_paths queue
def gather_paths():
    for root, _, files in os.walk('.'):
        for fname in files:
            if os.path.splitext(fname)[1] in FILTERED:
                continue
            path = os.path.join(root, fname)
            if path.startswith('.'):
                path = path[1:]
            print(path)
            web_paths.put(path)

def test_remote():
    # continue until web_paths queue is empty
    while not web_paths.empty():
        # get a path from the web_paths queue, construct the URL, and make a request to the URL
        path = web_paths.get()
        url = f'{TARGET}{path}'
        time.sleep(2)
        r = requests.get(url)
        # add to answers queue if status code is 200, otherwise print an 'x' to indicate failure
        if r.status_code == 200:
            answers.put(url)
            sys.stdout.write('+')
        else:
            sys.stdout.write('x')
        sys.stdout.flush()

def run():
    mythreads = list()
    for i in range(THREADS):
        print(f'Spawning thread {i}')
        t = threading.Thread(target=test_remote)
        mythreads.append(t)
        t.start()
    for t in mythreads:
        t.join()

# allows execution of code in a different directory, returning to the original directory on exit
@contextlib.contextmanager
def chdir(path):
    """
    On enter, change directory to specified path.
    On exit, change directory back to original path.
    """
    this_dir = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        # always return to original directory, even if an error occurs
        os.chdir(this_dir) 

if __name__ == '__main__':
    # save original directory, change to wordpress directory, gather paths, and return to original directory
    with chdir("/home/majora/Downloads/wordpress"):
        gather_paths()
    input('Press Enter to continue...')
    run()
    with open('myanswers.txt', 'w') as f:
        while not answers.empty():
            f.write(answers.get() + '\n')
    print('\nDone! Results saved in myanswers.txt')