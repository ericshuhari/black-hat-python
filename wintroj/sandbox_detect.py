from ctypes import byref, c_uint, c_ulong, sizeof, Structure, windll
import random
import sys
import time
import win32api

# structure to hold timestamp (ms) of last input event detected by the system
class LASTINPUTINFO(Structure):
    _fields_ = [
        ('cbSize', c_uint),
        ('dwTime', c_ulong)
    ]

def get_last_input():
    struct_lastinputinfo = LASTINPUTINFO()
    # initialize cbSize field to the size of the structure
    struct_lastinputinfo.cbSize = sizeof(LASTINPUTINFO)
    # populate dwTime field with the timestamp of the last input event
    windll.user32.GetLastInputInfo(byref(struct_lastinputinfo))
    # determine system runtime
    run_time = windll.kernel32.GetTickCount()
    elapsed = run_time - struct_lastinputinfo.dwTime
    return elapsed

# test snippet
# while True:
#     get_last_input()
#     time.sleep(1)
#     print(f'Last input was {get_last_input()} ms ago')

class Detector:
    def __init__(self):
        self.double_clicks = 0
        self.keystrokes = 0
        self.mouse_clicks = 0

    def get_key_press(self):
        # iterate through all possible key codes
        for i in range(0, 0xff):
            # check if the key was pressed
            state = win32api.GetAsyncKeyState(i)
            
            if state & 0x0001:
                # increment mouse clicks if the key was a left mouse click
                if i == 0x1:
                    self.mouse_clicks += 1
                    return time.time()
                # increment keystrokes if the key was an ASCII-printable character
                elif i > 32 and i < 127:
                    self.keystrokes += 1
        return None
    
    def detect(self):
        previous_timestamp = None
        first_double_click = None
        double_click_threshold = 0.35

        # track timing of mouse clicks and keystrokes, set thresholds to determine if the activity is human-like or automated
        max_double_clicks = 10
        max_keystrokes = random.randint(10, 25)
        max_mouse_clicks = random.randint(5, 25)
        max_input_threshold = 30000

        # time since last detected input, exit if it exceeds the threshold
        # TODO: consider additional functionality instead of exiting
        last_input = get_last_input()
        if last_input >= max_input_threshold:
            sys.exit(0)
        

        detection_complete = False
        while not detection_complete:
            # check for key presses and mouse clicks
            keypress_time = self.get_key_press()
            if keypress_time is not None and previous_timestamp is not None:
                # calculate time between inputs
                elapsed = keypress_time - previous_timestamp

                # check for double click
                if elapsed <= double_click_threshold:
                    self.mouse_clicks -= 2
                    self.double_clicks += 1
                    if first_double_click is None:
                        first_double_click = time.time()
                    else:
                        # check for double-click spamming, exit if exceeding threshold
                        if self.double_clicks >= max_double_clicks:
                            if (keypress_time - first_double_click <= (max_double_clicks * double_click_threshold)):
                                sys.exit(0)
                
                # exit sandbox detection if conditions are exceeded, otherwise update previous timestamp
                if (self.keystrokes >= max_keystrokes and self.double_clicks >= max_double_clicks and self.mouse_clicks >= max_mouse_clicks):
                    detection_complete = True
                previous_timestamp = keypress_time
            elif keypress_time is not None:
                previous_timestamp = keypress_time



if __name__ == '__main__':
    d = Detector()
    d.detect()
    print('okay.')