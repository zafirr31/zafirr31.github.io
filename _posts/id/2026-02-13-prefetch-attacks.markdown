---
layout: post
author: zafirr
title:  "Prefetch attacks"
description: Indo-focused vulnerability research post 1
date: 2026-02-13
last_modified_at: 2026-02-17
categories: research
lang: id
tags:
    - ctf
    - vulnerability research
    - series
---

<br>

### ASLR
ASLR merupakan singkatan dari [Address Space Layout Randomization](https://en.wikipedia.org/wiki/Address_space_layout_randomization), yaitu teknik yang digunakan oleh sistem operasi untuk mengamankan proses di user space terhadap eksploitasi dengan _memory corruption_. Ini dicapai dengan meletakkan alamat kode atau data pada sebuah proses di lokasi yang acak, sehingga seorang penyerang tidak tau dimana letaknya yang pasti. Pada sistem operasi modern seperti Linux, Windows, dan MacOS, letak alamat pada kernel juga diacak. Hal ini disebut dengan [KASLR](https://lwn.net/Articles/569635/) (Kernel Address Space Layout Randomization). Linux sendiri sudah menggunakan KASLR sejak 2014. Untuk mempermudah, blog ini akan menggunakan sistem operasi Linux (di x86), tetapi hal yang dipelajari _mungkin_ dapat diterapkan di sistem lain.

Cara kerja ASLR (dan KASLR) adalah dengan mengacak lokasi dasar dari sebuah bagian memori. Jika bagian memori tersebut sebesar N _page_ (1 _page_ adalah 4096 byte pada sebagian besar sistem operasi), maka N _page_ tersebut akan selalu berurutan, tetapi alamat dasarnya akan diacak. Sebagai contoh, jika sebuah proses membutuhkan sebesar 10 _page_, maka Linux akan memilih secara acak lokasi untuk _page_ pertama, lalu menempatkan _page_ sisanya berdasarkan urutan yang dibutuhkan proses tersebut. Hal ini mempermudah dan mempercepat penerapan ASLR, sehingga tidak melambatkan performa sistem terlalu drastis.

Terdapat berbagai cara untuk mengalahkan ASLR, yang paling sering digunakan adalah mendapatkan alamat dari satu lokasi pada sebuah bagian memori (sering disebut _leak_ (bocoran)). Dikarenakan ASLR menempatkan semua _page_ pada sebuah bagian memori sesuai dengan urutan yang dibutuhkan proses tersebut, maka dengan menambahkan atau mengurangi _leak_ tersebut dengan nilai konstan, maka kita bisa mendapatkan alamat bagian kode manapun.

> Catatan: Ini merupakan trik yang sangat basic yang digunakan di dunia _binary exploitation_, dan dapat dipelajari dengan menyelesaikan soal CTF yang simpel.

KASLR bersifat sama. Ketika komputer dinyalakan, sistem akan menempatkan beberapa bagian memori kernel pada lokasi tertentu. Sebagai catatan di (Linux) kernel terdapat berbagai bagian memori yang berbeda. Tujuan masing-masing bagian tersebut diluar cakupan blog ini, tapi garis besarnya dapat dilihat [disini](https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt). Jadi, ketika ingin mengalahkan KASLR untuk bagian _kernel text_, kita mesti mendapatkan _leak_ dari salah satu alamat di _kernel text_. Setelah itu, dengan menambakan atau mengurangi _leak_ tersebut, maka seluruh _kernel text_ dapat diketahui.

Biasanya, sebuah _leak_ didapatkan dengan sebuah bug pada kernel. Contohnya adalah [CVE-2024-26816](https://nvd.nist.gov/vuln/detail/CVE-2024-26816). Akan tetapi, di blog ini kita bakal melihat sebuah "bug" pada CPU, khususnya CPU Intel dan AMD (x86).

### _Prefetch_
Kalo diperhatikan, komputer zaman sekarang sudah luar biasa kencang. Alasan terbesar adalah kemajuan pada pembuatan komponen komputer, tapi alasan lain ada pada desain komponennya. Pada CPU sendiri, konsep seperti [_pipelining_](https://en.wikipedia.org/wiki/Instruction_pipelining) dan [_caching_](https://en.wikipedia.org/wiki/CPU_cache) sangat membantu untuk meningkatkan performa CPU. Selain itu, terdapat berbagai trik pada level perangkat lunak yang dapat digunakan untuk meningkatkan performa. Salah satunya adalah menggunakan _instruction set_ yang lebih kompleks seperti _instruction set_ AVX, yang dapat melakukan komputasi dengan ukuran _register_ yang lebih besar dalam satu instruksi.

Yang ingin kita dalami adalah instruksi [_PREFETCHh_](https://www.felixcloutier.com/x86/prefetchh). Ini merupakan instruksi yang membantu meningkatkan performa dengan cara mengambil data dari memori dan menyimpannya di _cache_ sebelum dilakukan instruksi _load_ beneran. Cara kerjanya berbeda2 untuk masing-masing CPU, dan pembahasan mengenai cara _prefetch_ diimplementasikan diluar cakupan blog ini (Ini sebenarnya alasan saja karena saya pun tidak ngerti).

Yang menarik dari instruksi _PREFETCHh_ adalah ketiadaan pengecekan _privilege level_. Artinya, user biasa (_unprivileged user_) dapat melakukan _prefetch_ pada alamat memory manapun, termasuk alamat memori kernel*. Ini bukan berarti data yang terdapat pada memori kernel dapat diakses (catatan: Meltdown & Spectre), tapi memori tersebut tetap akan diambil dan disimpan di _cache_ CPU. Level cachenya bergantung pada variasi _prefetch_ yang kita lakukan, dan perbedaan diluar cakupan blog ini.

> Coba berpikir untuk sejenak mengenai paragraf sebelumnya. Seorang _unprivileged user_ bisa _prefetch_ alamat kernel, tapi ngak bisa diakses. Bagaimana bisa leak alamat kernel kalau ngak bisa diakses?

\*Jika KPTI hidup, alamat memori kernel juga tidak dapat dilakukan _prefetch_. Pengecualikan ada pada [CVE-2022-4543](https://www.willsroot.io/2022/12/entrybleed.html)

<br>
<br>
<br>

### _Sidechannel_
Kita bisa menggunakan sebuah teknik bernama _sidechannel_ untuk mendapatkan _leak_ alamat memori kernel. Menurut riset dari [Gruss et.al](https://gruss.cc/files/prefetch.pdf), kita bisa mengukur waktu yang dibutuhkan untuk prefetch sebuah alamat memori kernel. Sebuah alamat memori yang valid akan berhasil dilakukan _prefetch_, sedangkan alamat memori yang invalid tidak akan berhasil. Oleh karena itu, jika dilakukan prefetch beberapa kali pada alamat yang sama, alamat memori yang valid membutuhkan **waktu yang lebih singkat**, disebabkan alamat memori tersebut sudah tersimpan pada cache CPU. Jadi, kita bisa mencoba seluruh kemungkinan kernel address (di x86, area .text hanya ada [512 kemungkinan!](https://github.com/torvalds/linux/blob/9702969978695d9a699a1f34771580cdbb153b33/arch/x86/Kconfig#L2108)) dan melakukan _prefetch_ pada alamat tersebut. Alamat yang valid akan berhasil di _prefetch_, dan waktu yang dibutuhkan akan lebih singkat dibanding alamat yang tidak valid.

Secara singkat, pengukuran lamanya _prefetch_ dapat dilakukan dengan potongan kode berikut (dari [https://www.willsroot.io/2022/12/entrybleed.html](https://www.willsroot.io/2022/12/entrybleed.html)):

```c
uint64_t sidechannel(uint64_t addr) {
    uint64_t a, b, c, d;
    asm volatile(".intel_syntax noprefix;"
                 "mfence;"
                 "lfence;"
                 "rdtsc;"
                 "mov %0, rax;"
                 "mov %1, rdx;"
                 "xor rax, rax;"
                 "lfence;"
                 "prefetchnta qword ptr [%4];"
                 "prefetcht2 qword ptr [%4];"
                 "xor rax, rax;"
                 "lfence;"
                 "rdtsc;"
                 "mov %2, rax;"
                 "mov %3, rdx;"
                 "mfence;"
                 ".att_syntax;"
                 : "=r"(a), "=r"(b), "=r"(c), "=r"(d)
                 : "r"(addr)
                 : "rax", "rbx", "rcx", "rdx");
    a = (b << 32) | a;
    c = (d << 32) | c;
    return c - a; // timing difference
}
```

Kode untuk mendapatkan _leak_ alamat memori kernel secara lengkap dapat dicari pada sumber lain, atau menjadi bahan latihan.

### Latihan
Coba buat / minta AI untuk buat sebuah challenge CTF, dimana user diberikan cara untuk menjalankan _shellcode_ dan mesti mencari cara untuk membaca flag yang disimpan pada sebuah alamat random. Gunakan _prefetch_ attack buat leak alamat flagnya, lalu cetak flagnya.

Terdapat juga challenge di [Dreamhack](https://dreamhack.io/wargame/challenges/1055) dengan konsep yang sama.

### Penutup
Bila tertarik pelajari lebih lanjut, kalian bisa mendalami:

- Meltdown
- Spectre
- KPTI
- Entrybleed

<br>
Dan diluar ranah _binary exploitation_:

- _Timing attacks_ di kriptografi

<br>
Terima kasih sudah membaca

### Referensi
* [https://gruss.cc/files/prefetch.pdf](https://gruss.cc/files/prefetch.pdf)
* [https://www.felixcloutier.com/x86/prefetchh](https://www.felixcloutier.com/x86/prefetchh)
* [https://www.willsroot.io/2022/12/entrybleed.html](https://www.willsroot.io/2022/12/entrybleed.html)
* [https://u1f383.github.io/linux/2025/01/02/linux-kaslr-entropy.html](https://u1f383.github.io/linux/2025/01/02/linux-kaslr-entropy.html)
* [https://lwn.net/Articles/569635/](https://lwn.net/Articles/569635/)
* [https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt](https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt)