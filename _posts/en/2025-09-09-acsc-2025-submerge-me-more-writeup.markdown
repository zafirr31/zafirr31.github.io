---
layout: post
author: zafirr
title:  "ACSC 2025 Submerge Me More writeup"
description: pwning ring -2 
date: 2025-09-09
last_modified_at: 2025-09-09
categories: writeup
lang: en
tags:
    - ctf
    - pwn
    - ring -2 
    - smm 
    - buffer overflow
---

<br>
This year, acsc was conducted by dreamhack. I think there were some problems with the CTF, but overall the challenges were good and up to standard with what I expect with acsc. I played for a bit, but stopped after a few hours. There were 2 challenges I wanted to upsolve, [ebpf confusion](https://dreamhack.io/wargame/challenges/2217) and [submerge me more](https://dreamhack.io/wargame/challenges/2234). This post is a writeup for submerge me more, and maybe I'll make another for ebpf confusion in the future.

I highly recommend trying them both out. ebpf confusion is a bit harder, but it mimicks CVEs related to ebpf quite a bit.

You can download the challenge files [here](https://dreamhack.io/wargame/challenges/2234), however please note you need to create an account on dreamhack to do so.


## Submerge Me More
Since I started working on it after the CTF, I did get a bit of insight for the challenge.

![Error](/assets/images/acsc_2025_submerge_me_more/1.png)

Ok, it seems we are given a vulnerable SMM Module in a UEFI file. WE can extract the SMM Module using [UEFI Tool](https://github.com/LongSoft/UEFITool)

We can find the SMM Module called "ChallengeModule"

![Error](/assets/images/acsc_2025_submerge_me_more/2.png)

We can then extract the PE Image Section, which we can then decompile with IDA/Ghidra/Binja

According to the challenge author, he used [efiXplorer](github.com/binarly-io/efiXplorer) to help with the reversing. This is because without it, many of the EFI functions are unknown to us.

![Error](/assets/images/acsc_2025_submerge_me_more/3.png)

However, I could not get efiXplorer to work on my version of IDA, so instead I used [efiSeek](https://github.com/DSecurity/efiSeek) for Ghidra, the project is a bit outdated, but luckily we can update the gradle.build and recompile it for recent versions of ghidra. There are also online forks that solve this issue (example: [this fork](https://github.com/DisplayGFX/efiSeek))

Now, the efi functions are known to us

![Error](/assets/images/acsc_2025_submerge_me_more/4.png)

Its not too hard to find the vulnerable function. I quickly found `ChildSmiHandler6` which is the vulnerable function.

## Interaction with ChildSmiHandler6
To exploit the handler, we first need to find out how to interact with it. In fact, this is the hardest part of the challenge 😂. To help with this, we can look for previous CTF writeups about SMM Module exploitation. Here are 3 I found very helpful to me when solving this challenge:

* [https://www.willsroot.io/2023/08/smm-diary-writeup.html](https://www.willsroot.io/2023/08/smm-diary-writeup.html)
* [https://blog.libh0ps.so/2023/08/02/corCTF2023.html](https://blog.libh0ps.so/2023/08/02/corCTF2023.html)
* [https://towerofhanoi.it/writeups/2022-08-15-uiuctf-2022-smm-cowsay/](https://towerofhanoi.it/writeups/2022-08-15-uiuctf-2022-smm-cowsay/)

All three of these writeups are very recommended, there's a lot to learn from them.

However, both of those challenges are run in ring 0 (kernel space). But in the case of this challenge, we are in ring 3 as the root user 🫤. This means we wont be able to use their methods to interact with the SMM Module, atleast not fully.

> This is a good point to try the challenge for yourself. There is a neat trick we can use to interact with the SMM Module.

<br>
<br>
<br>

My first idea was to create a kernel module, similar to the corctf authors' method. However, this challenge does not provide the headers to do so, and it does not give us the Kconfig. The kernel is not compiled with CONFIG_IKCONFIG either, which means we cannot use extract_ikconfig either to get it.

My second idea is to take an existing kernel module, and rewriting the init function with our own shellcode. This method is what me and [nyancat0131](https://x.com/bienpnn) did during blackhat MEA 2024 finals. Believe it or not, this works, but it's very annoying to do if you dont really understand ELF files.

After looking online a bit more, I found [this](https://groups.google.com/g/comp.os.linux.development.apps/c/2kiUc-dNa3c) google group discussion about mapping a physical address using mmap. We can use this 6th argument (offset) to map any physical address with /dev/mem as the file. Since we are root and /dev/mem is available, this method works perfectly 😄

> Small Quiz: How do we handle ASLR?

<br>

From here, we can follow the method described in the corctf challenge writeup. First, we need to find the gSmmCorePrivate struct. There are scripts by [binarly](https://github.com/chipsec/chipsec/blob/c5e396716caf3749f728e43d0895317b593f5b95/chipsec/hal/interrupts.py#L139), but I wasn't able to get it to work and I was a bit lazy. Instead, I just created a breakpoint at the ModuleEntryPoint for ChallengeModule. Pwndbg can detect other valid memory mappings and we can add them during our debug

![Error](/assets/images/acsc_2025_submerge_me_more/5.png)

Then, we can just do `search -t string smmc` and it's easily found

![Error](/assets/images/acsc_2025_submerge_me_more/6.png)

Then we just set the CommBuffer just like the corctf writeup

> Sorry for skipping a lot of details, I didn't want to parrot things that are already explained in the other 3 writeups.

## Pwning time!
Let's take a look again at ChildSmiHandler6.

```c

undefined8
ChildSmiHandler6(undefined8 param_1,undefined8 param_2,undefined4 *CommBuffer,
                ulonglong *CommBufferSize)

{
  undefined1 uVar1;
  char cVar2;
  longlong lVar3;
  ulonglong uVar4;
  longlong lVar5;
  char *pcVar6;
  int iVar7;
  ulonglong uVar8;
  char *pcVar9;
  undefined4 *puVar10;
  byte local_68 [64];
  
  if ((CommBuffer == (undefined4 *)0x0) || (CommBufferSize == (ulonglong *)0x0)) {
    return 0x8000000000000002;
  }
  if (*CommBufferSize < 0xe0) {
    return 0x8000000000000002;
  }
  switch(*CommBuffer) {
  case 1:
    puVar10 = CommBuffer;
    cVar2 = .text();
    pcVar9 = (char *)(puVar10 + 2);
    if (cVar2 != '\0') {
      FUN_7ff9cc69(0x40);
    }
    lVar5 = 0;
    do {
      lVar3 = lVar5 + 1;
      if (s_Hello_from_SMM!_7ff9db8b[lVar5 + 1] == '\0') {
        if (s_Hello_from_SMM!_7ff9db8b <= pcVar9) {
          if (pcVar9 < s_Hello_from_SMM!_7ff9db8b + lVar5 + 2) break;
          pcVar6 = s_Hello_from_SMM!_7ff9db8b;
          if (pcVar9 != s_Hello_from_SMM!_7ff9db8b) goto LAB_7ff9cfeb;
        }
        pcVar6 = s_Hello_from_SMM!_7ff9db8b;
        if (puVar10 + 0x12 < s_Hello_from_SMM!_7ff9db8b + 1) goto LAB_7ff9cfeb;
        break;
      }
      lVar5 = lVar3;
    } while (lVar3 != 0x3f);
    if (cVar2 != '\0') {
      FUN_7ff9cc69(0x400000);
    }
    break;
  case 2:
    CommBuffer[4] = CommBuffer[3] + CommBuffer[2];
    break;
  case 3:
    pcVar9 = (char *)(CommBuffer + 2);
    uVar4 = FUN_7ff9c0e7((longlong)pcVar9);
    if (uVar4 == 0xffffffffffffffff) {
      FUN_7ff9c079();
    }
    uVar4 = FUN_7ff9c0e7((longlong)(CommBuffer + 0x12));
    if (uVar4 == 0xffffffffffffffff) {
      FUN_7ff9c079();
    }
    while( true ) {
      cVar2 = *pcVar9;
      if ((cVar2 == '\0') || (cVar2 != pcVar9[0x40])) break;
      pcVar9 = pcVar9 + 1;
    }
    *(bool *)(CommBuffer + 0x22) = pcVar9[0x40] == cVar2;
    break;
  case 4:
    uVar4 = FUN_7ff9c0e7((longlong)(CommBuffer + 2));
    lVar5 = uVar4 + (longlong)CommBuffer;
    for (uVar8 = 0; uVar8 != uVar4 >> 1; uVar8 = uVar8 + 1) {
      uVar1 = *(undefined1 *)((longlong)CommBuffer + uVar8 + 8);
      *(undefined1 *)((longlong)CommBuffer + uVar8 + 8) = *(undefined1 *)(lVar5 + 7);
      *(undefined1 *)(lVar5 + 7) = uVar1;
      lVar5 = lVar5 + -1;
    }
    break;
  case 5:
    uVar8 = *(ulonglong *)(CommBuffer + 2);
    uVar4 = uVar8 - 1;
    if (199 < uVar4) goto switchD_00001d8a_default;
    if (~(ulonglong)local_68 < uVar4) {
      FUN_7ff9c079();
    }
    if (~(ulonglong)(CommBuffer + 4) < uVar4) {
      FUN_7ff9c079();
    }
    bug_here?((undefined8 *)local_68,(undefined8 *)(CommBuffer + 4),uVar8); // renamed function
    iVar7 = 0;
    for (lVar5 = 0; lVar5 != *(longlong *)(CommBuffer + 2); lVar5 = lVar5 + 1) {
      iVar7 = iVar7 + (uint)local_68[lVar5];
    }
    CommBuffer[0x36] = iVar7;
    break;
  default:
switchD_00001d8a_default:
    CommBuffer[1] = 0xffffffff;
    return 0;
  }
LAB_7ff9cf1d:
  CommBuffer[1] = 0;
  return 0;
LAB_7ff9cfeb:
  for (; *pcVar6 != '\0'; pcVar6 = pcVar6 + 1) {
    *pcVar9 = *pcVar6;
    pcVar9 = pcVar9 + 1;
  }
  *pcVar9 = '\0';
  goto LAB_7ff9cf1d;
}
```

It seems the first word (4 bytes) in CommBuffer is passed to a switch case. The first switch case just writes "Hello from SMM!" in to the CommBuffer. This is a great method to test if communication with the handler was successful or not. The second until fourth ones aren't too important. The fifth case is interesting. There is a call to a function (i renamed it bug_here?, there are no debug symbols), which seems to implement memcpy. It will copy the data from CommBuffer into local_68, which is an array of length 64. The length we pass to memcpy cannot be larger than 199, but this is more than enough to do a buffer overflow and ROP. Using this ROP, we can leak the hardcoded flag which is stored at the address 0x7ff9ddf6

## Closing
Since this challenge is used as a wargame challenge on Dreamhack, I think it's best if I do not provide my exploit script. This writeup and the previous writeups are more than enough information to solve this challenge. As a stepping stone, you can copy the exploit from corctf and replace the ioremap calls with mmap calls. From there, focus on trying to interact with the handler. Once you can, the exploitation is really easy. Good luck!

> Answer to quiz: There is no ASLR. We can leak the base address for every module / efi file using debugcon flag to qemu. This is explained in the writeup by mebeim (towerofhanoi player) I provided previously