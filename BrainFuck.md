*Brain fuck write up*
This did hurt my head but a once as I got my head over it, it wasn't too bad. 

_
I made a simple brain-fuck language emulation program written in C. 
The [ ] commands are not implemented yet. However the rest functionality seems working fine. 
Find a bug and exploit it to get a shell. 

Download : http://pwnable.kr/bin/bf
Download : http://pwnable.kr/bin/bf_libc.so

Running at : nc pwnable.kr 9001
*checksec bf*

*Stage one. What am I working with?...*
check
<code>
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
    
</code>

<p> 
We have a 32bit file with a canray which may be detected if we just jump in with a buffer overflow. 
With it having NX enabled we will have to do a ROP chain on this one. 
</p>

*Stage two have a look* 
<code>

(gdb) disassemble main
Dump of assembler code for function main:
   0x08048671 <+0>:	push   %ebp
   0x08048672 <+1>:	mov    %esp,%ebp
   0x08048674 <+3>:	push   %ebx
   0x08048675 <+4>:	and    $0xfffffff0,%esp
   0x08048678 <+7>:	sub    $0x430,%esp
   0x0804867e <+13>:	mov    0xc(%ebp),%eax
   0x08048681 <+16>:	mov    %eax,0x1c(%esp)
   0x08048685 <+20>:	mov    %gs:0x14,%eax
   0x0804868b <+26>:	mov    %eax,0x42c(%esp)
   0x08048692 <+33>:	xor    %eax,%eax
   0x08048694 <+35>:	mov    0x804a060,%eax
   0x08048699 <+40>:	movl   $0x0,0xc(%esp)
   0x080486a1 <+48>:	movl   $0x2,0x8(%esp)
   0x080486a9 <+56>:	movl   $0x0,0x4(%esp)
   0x080486b1 <+64>:	mov    %eax,(%esp)
   0x080486b4 <+67>:	call   0x80484b0 <setvbuf@plt>
   0x080486b9 <+72>:	mov    0x804a040,%eax
   0x080486be <+77>:	movl   $0x0,0xc(%esp)
   0x080486c6 <+85>:	movl   $0x1,0x8(%esp)
   0x080486ce <+93>:	movl   $0x0,0x4(%esp)
   0x080486d6 <+101>:	mov    %eax,(%esp)
   0x080486d9 <+104>:	call   0x80484b0 <setvbuf@plt>
--Type <RET> for more, q to quit, c to continue without paging--
   0x080486de <+109>:	movl   $0x804a0a0,0x804a080
   0x080486e8 <+119>:	movl   $0x804890c,(%esp)
   0x080486ef <+126>:	call   0x8048470 <puts@plt>
   0x080486f4 <+131>:	movl   $0x8048934,(%esp)
   0x080486fb <+138>:	call   0x8048470 <puts@plt>
   0x08048700 <+143>:	movl   $0x400,0x8(%esp)
   0x08048708 <+151>:	movl   $0x0,0x4(%esp)
   0x08048710 <+159>:	lea    0x2c(%esp),%eax
   0x08048714 <+163>:	mov    %eax,(%esp)
   0x08048717 <+166>:	call   0x80484c0 <memset@plt> <---- interesting 
   0x0804871c <+171>:	mov    0x804a040,%eax
   0x08048721 <+176>:	mov    %eax,0x8(%esp) <--- interesting
   0x08048725 <+180>:	movl   $0x400,0x4(%esp)
   0x0804872d <+188>:	lea    0x2c(%esp),%eax
   0x08048731 <+192>:	mov    %eax,(%esp)
   0x08048734 <+195>:	call   0x8048450 <fgets@plt>   <----- Interesting
   0x08048739 <+200>:	movl   $0x0,0x28(%esp)
   0x08048741 <+208>:	jmp    0x8048760 <main+239>
   0x08048743 <+210>:	lea    0x2c(%esp),%edx
   0x08048747 <+214>:	mov    0x28(%esp),%eax
   0x0804874b <+218>:	add    %edx,%eax
   0x0804874d <+220>:	movzbl (%eax),%eax
   0x08048750 <+223>:	movsbl %al,%eax
   0x08048753 <+226>:	mov    %eax,(%esp)
   0x08048756 <+229>:	call   0x80485dc <do_brainfuck> <--- Main function ------>
   0x0804875b <+234>:	addl   $0x1,0x28(%esp)
   0x08048760 <+239>:	mov    0x28(%esp),%ebx
   0x08048764 <+243>:	lea    0x2c(%esp),%eax
   0x08048768 <+247>:	mov    %eax,(%esp)
   0x0804876b <+250>:	call   0x8048490 <strlen@plt>
   0x08048770 <+255>:	cmp    %eax,%ebx
   0x08048772 <+257>:	jb     0x8048743 <main+210>
   0x08048774 <+259>:	mov    $0x0,%eax
   0x08048779 <+264>:	mov    0x42c(%esp),%edx
   0x08048780 <+271>:	xor    %gs:0x14,%edx
   0x08048787 <+278>:	je     0x804878e <main+285>
   0x08048789 <+280>:	call   0x8048460 <__stack_chk_fail@plt>
   0x0804878e <+285>:	mov    -0x4(%ebp),%ebx
   0x08048791 <+288>:	leave  
   0x08048792 <+289>:	ret    
End of assembler dump.
(gdb) 

-----Brain fuck function------

(gdb) disassemble do_brainfuck
Dump of assembler code for function do_brainfuck:
   0x080485dc <+0>:	push   %ebp
   0x080485dd <+1>:	mov    %esp,%ebp
   0x080485df <+3>:	push   %ebx
   0x080485e0 <+4>:	sub    $0x24,%esp
   0x080485e3 <+7>:	mov    0x8(%ebp),%eax
   0x080485e6 <+10>:	mov    %al,-0xc(%ebp)
   0x080485e9 <+13>:	movsbl -0xc(%ebp),%eax
   0x080485ed <+17>:	sub    $0x2b,%eax
   0x080485f0 <+20>:	cmp    $0x30,%eax
   0x080485f3 <+23>:	ja     0x804866b <do_brainfuck+143>
   0x080485f5 <+25>:	mov    0x8048848(,%eax,4),%eax
   0x080485fc <+32>:	jmp    *%eax
   0x080485fe <+34>:	mov    0x804a080,%eax
   0x08048603 <+39>:	add    $0x1,%eax
   0x08048606 <+42>:	mov    %eax,0x804a080
   0x0804860b <+47>:	jmp    0x804866b <do_brainfuck+143>
   0x0804860d <+49>:	mov    0x804a080,%eax
   0x08048612 <+54>:	sub    $0x1,%eax
   0x08048615 <+57>:	mov    %eax,0x804a080
   0x0804861a <+62>:	jmp    0x804866b <do_brainfuck+143>
   0x0804861c <+64>:	mov    0x804a080,%eax
   0x08048621 <+69>:	movzbl (%eax),%edx
   0x08048624 <+72>:	add    $0x1,%edx
   0x08048627 <+75>:	mov    %dl,(%eax)
   0x08048629 <+77>:	jmp    0x804866b <do_brainfuck+143>
   0x0804862b <+79>:	mov    0x804a080,%eax
   0x08048630 <+84>:	movzbl (%eax),%edx
   0x08048633 <+87>:	sub    $0x1,%edx
   0x08048636 <+90>:	mov    %dl,(%eax)
   0x08048638 <+92>:	jmp    0x804866b <do_brainfuck+143>
   0x0804863a <+94>:	mov    0x804a080,%eax
   0x0804863f <+99>:	movzbl (%eax),%eax
   0x08048642 <+102>:	movsbl %al,%eax
   0x08048645 <+105>:	mov    %eax,(%esp)
   0x08048648 <+108>:	call   0x80484d0 <putchar@plt>
   0x0804864d <+113>:	jmp    0x804866b <do_brainfuck+143>
   0x0804864f <+115>:	mov    0x804a080,%ebx
   0x08048655 <+121>:	call   0x8048440 <getchar@plt>
   0x0804865a <+126>:	mov    %al,(%ebx)
   0x0804865c <+128>:	jmp    0x804866b <do_brainfuck+143>
   0x0804865e <+130>:	movl   $0x8048830,(%esp)
   0x08048665 <+137>:	call   0x8048470 <puts@plt>
   0x0804866a <+142>:	nop
   0x0804866b <+143>:	add    $0x24,%esp
   0x0804866e <+146>:	pop    %ebx
   0x0804866f <+147>:	pop    %ebp
   0x08048670 <+148>:	ret 
</code>


<code>
I cant copy some of the dump from EDB there is a pointer 
0x804a0a0 to a funciton we need to use. 

</code>
<p>
so we need to write a rop gadget soon, we use a sys func in the code to overwrite. 
</P
<p>
call a new function we write use brain fuck to help us 
</p>
<p>
The two mostly fun functions are memstet and fgets:
https://pvs-studio.com/en/blog/posts/cpp/0360/
</p>
Time to find theese Addresses 
<code>
YNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE 
08049ffc R_386_GLOB_DAT    __gmon_start__
0804a040 R_386_COPY        stdin@@GLIBC_2.0
0804a060 R_386_COPY        stdout@@GLIBC_2.0
0804a00c R_386_JUMP_SLOT   getchar@GLIBC_2.0
0804a010 R_386_JUMP_SLOT   fgets@GLIBC_2.0 <-----Here
0804a014 R_386_JUMP_SLOT   __stack_chk_fail@GLIBC_2.4
0804a018 R_386_JUMP_SLOT   puts@GLIBC_2.0
0804a01c R_386_JUMP_SLOT   __gmon_start__
0804a020 R_386_JUMP_SLOT   strlen@GLIBC_2.0
0804a024 R_386_JUMP_SLOT   __libc_start_main@GLIBC_2.0
0804a028 R_386_JUMP_SLOT   setvbuf@GLIBC_2.0
0804a02c R_386_JUMP_SLOT   memset@GLIBC_2.0  <------- Here 
0804a030 R_386_JUMP_SLOT   putchar@GLIBC_2.0
</code> 



