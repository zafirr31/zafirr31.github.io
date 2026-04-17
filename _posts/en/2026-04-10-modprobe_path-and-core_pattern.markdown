---
layout: post
author: zafirr
title:  "modprobe_path and core_pattern"
description: Indo-focused vulnerability research post 2
date: 2026-04-10
last_modified_at: 2026-04-10
categories: research
lang: en
tags:
    - ctf
    - vulnerability research
    - series
---

<br>
Difficulty: **Easy**

<br>
This blog post was intended for Indonesian audiences. I'm only including the exercise portion and references that I used to create the blog post for the English version.

Files I used for examples can downloaded [here](https://drive.google.com/drive/folders/1RlTVnCE3zoc2KMBu8T4zg0VzZVg9sZHJ?usp=sharing)

### References
* [https://lkmidas.github.io/posts/20210223-linux-kernel-pwn-modprobe/](https://lkmidas.github.io/posts/20210223-linux-kernel-pwn-modprobe/)
* [https://theori.io/blog/reviving-the-modprobe-path-technique-overcoming-search-binary-handler-patch](https://theori.io/blog/reviving-the-modprobe-path-technique-overcoming-search-binary-handler-patch)
* [KernelCTF](https://github.com/google/security-research/tree/master/kernelctf)
* Coworkers

### Exercise
Both tricks run a custom saved program as root. However, what if our current user is in a namespace, how can the user escape from the namespace (example: from inside docker)?

There are techniques you can find at [kernelctf](https://github.com/google/security-research/tree/master/kernelctf), feel free to explore the techniques yourself.