---
layout: post
author: zafirr
title:  "Prefetch attacks"
description: Indo-focused vulnerability research post 1
date: 2026-02-13
last_modified_at: 2026-02-17
categories: research
lang: en
tags:
    - ctf
    - vulnerability research
    - series
---

<br>
This blog post was intended for Indonesian audiences. I'm only including the exercise portion and references that I used to create the blog post for the English version.

### References
* [https://gruss.cc/files/prefetch.pdf](https://gruss.cc/files/prefetch.pdf)
* [https://www.felixcloutier.com/x86/prefetchh](https://www.felixcloutier.com/x86/prefetchh)
* [https://www.willsroot.io/2022/12/entrybleed.html](https://www.willsroot.io/2022/12/entrybleed.html)
* [https://u1f383.github.io/linux/2025/01/02/linux-kaslr-entropy.html](https://u1f383.github.io/linux/2025/01/02/linux-kaslr-entropy.html)
* [https://lwn.net/Articles/569635/](https://lwn.net/Articles/569635/)
* [https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt](https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt)

### Exercise
Try to create / ask AI to create a CTF challenge where the user is asked to run shellcode, and must find the flag which is stored at a random address in memory. Use a prefetch attack to leak the address of the flag, then print the flag.

There is also a challenge on [Dreamhack](https://dreamhack.io/wargame/challenges/1055) with the same concept.

