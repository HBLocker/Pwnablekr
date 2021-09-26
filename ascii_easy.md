
We often need to make 'printable-ascii-only' exploit payload.  You wanna try?

hint : you don't necessarily have to jump at the beggining of a function. try to land anyware.


ssh ascii_easy@pwnable.kr -p2222 (pw:guest)



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


