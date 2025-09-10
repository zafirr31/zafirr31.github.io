---
layout: post
author: zafirr
title:  "ACSC 2025 Submerge Me More writeup"
description: pwning ring -2 
date: 2025-09-09
last_modified_at: 2025-09-09
categories: writeup
lang: id 
tags:
    - ctf
    - pwn
    - ring -2 
    - smm 
    - buffer overflow
---

<br>
Tahun ini, acsc diselenggarakan dreamhack. Menurut aku ada beberapa isu dengan CTFnya, tapi secara umum soalnya lumayan bagus dan mencapai ekspektasiku untuk acsc. Aku gak main lama, cuma beberapa jam terus capek. Ada 2 soal yang aku pengen upsolve, [ebpf confusion](https://dreamhack.io/wargame/challenges/2217) dan [submerge me more](https://dreamhack.io/wargame/challenges/2234). Writeup ini untuk submerge me more, tapi mungkin nanti aku buat writeup untuk ebpf confusion juga.

Sangat dianjurkan untuk mencoba kedua soal tersebut. ebpf confusion menurut aku lebih sulit, tapi soalnya lumayan mirip dengan CVE ebpf yang lain.

Soalnya dapat didownload [di sini](https://dreamhack.io/wargame/challenges/2234), tapi perlu buat akun dreamhack dulu.

## Submerge Me More
Karena aku mulai kerjain setelah CTFnya selesai, ada sedikit informasi tambahan untuk soal ini.

![Error](/assets/images/acsc_2025_submerge_me_more/1.png)

Oke, sepertinya kita diberikan module SMM di file UEFI yang ada bugnya. Kita bisa ekstrak module SMM tersebut dengan [UEFI Tool](https://github.com/LongSoft/UEFITool)

Module SMMnya diberi nama "ChallengeModule"

![Error](/assets/images/acsc_2025_submerge_me_more/2.png)

Kita bisa ekstrak PE Image Section, lalu bisa kita decompile dengan IDA/Ghidra/Binja

Menurut pembuat soalnya, dia menggunakan [efiXplorer](https://github.com/binarly-io/efiXplorer) untuk bantu reversing modulenya. Karena tanpa tool tersebut, sebagian besar fungsi efinya tidak diketahui.

![Error](/assets/images/acsc_2025_submerge_me_more/3.png)

Sayangnya efiXplorer gak berhasil jalan di versi IDAku, jadinya aku pake [efiSeek](https://github.com/DSecurity/efiSeek) dengan Ghidra. Projeknya agak tua, tapi untung nya kita tinggal perbarui file gradle.build terus compile ulang untuk versi ghidra yang terbaru. Ada beberapa fork yang udah fix isu (contoh: [ini](https://github.com/DisplayGFX/efiSeek))

Sekarang, fungsi efinya jadi jelas

![Error](/assets/images/acsc_2025_submerge_me_more/4.png)

Fungsi yang ada bugnya gak terlalu susah untuk dicari, setelah reversing beberapa menit ketemu fungsi `ChildSmiHandler6`.

## Cara interaksi dengan ChildSmiHandler6
Agar kita bisa exploit fungsi fungsi tersebut, kita perlu tau cara untuk interaksi dengannya. Ternyata, ini langkah paling sulit di soal ini wkwkwk. Kita bisa mencari beberapa writeup sebelumnya tentang eksploitasi module SMM. 3 writeup berikut sangat membantu:

* [https://www.willsroot.io/2023/08/smm-diary-writeup.html](https://www.willsroot.io/2023/08/smm-diary-writeup.html)
* [https://blog.libh0ps.so/2023/08/02/corCTF2023.html](https://blog.libh0ps.so/2023/08/02/corCTF2023.html)
* [https://towerofhanoi.it/writeups/2022-08-15-uiuctf-2022-smm-cowsay/](https://towerofhanoi.it/writeups/2022-08-15-uiuctf-2022-smm-cowsay/)

Sangat dianjurkan untuk membaca ketiga writeup tersebut, banyak hal yang bisa dipelajari

Bedanya, kedua soal yang dijelaskan di writeup diatas jalannya di ring 0 (kernel space). Dalam kasus ini, kita diletakkan di ring 3 sebagai user root 🫤. Jadi kita gak bisa gunakan secara penuh cara mereka untuk interaksi dengan module SMMnya, mesti cari cara lain.

> Ini merupakan tempat yang bagus untuk mencoba menyelesaikan soalnya secara sendiri. Ada trik yang mantap yang bisa digunakan untuk interaksi dengan module SMMnya.

<br>
<br>
<br>

Ide pertamaku adalah membuat module kernel, mirip dengan metode yang digunakan di corctf. Akan tetapi, soal ini gak kasih kita header files yang dibutuhkan, dan Kconfig juga tidak diberikan. Kernelnya gak dicompile dengan CONFIG_IKCONFIG juga, jadi kita gabisa menggunakan extract_ikconfig untuk mendapatnya.

Ide keduaku itu mengambil module kernel yang sudah ada, dan mengubah fungsi init dengan shellcode yang berbeda. Cara ini aku dan [nyancat0131](https://x.com/bienpnn) gunakan di final Blackhat MEA 2024. Menariknya, cara ini bisa, tapi lumayan ngeselin kalo gak begitu mengerti format file ELF.

Setelah mencari2 cara lagi, aku menemukan diskusi google group [ini](https://groups.google.com/g/comp.os.linux.development.apps/c/2kiUc-dNa3c) tentang pemetaan alamat fisik dengan mmap. Kita bisa menggukan argumen keenam (offset) untuk memetakan alamat fisik manapun menggunakan /dev/mem sebagai file. Karena kita root dan /dev/mem tersedia cara ini bisa kita gunakan 😄.

> Kuis singkat: Bagaiman dengan ASLR?

<br>

Dari sini, kita bisa ikuti cara yang dijelaskan di writeup soal corctf. Pertama, kita perlu mencari alamat dari gSmmCorePrivate. Terdapat script yang dibuat [binarly](https://github.com/chipsec/chipsec/blob/c5e396716caf3749f728e43d0895317b593f5b95/chipsec/hal/interrupts.py#L139), tapi aku gak berhasil jalanin dan malas debug banyak2. Jadi, aku kasih breakpoint aja di fungsi ModuleEntryPoint di ChallengeModule. Pwndbg bisa deteksi mapping lain yang valid, dan bisa kita tambahakan saat debug

![Error](/assets/images/acsc_2025_submerge_me_more/5.png)

Lalu, kita bisa gunakan command `search -t string smmc` saja

![Error](/assets/images/acsc_2025_submerge_me_more/6.png)

Terus bisa kita atur CommBuffer persis seperti writeup corctf

> Maaf kalo ada lewatin banyak detil, sebenarnya udah jelas di ketiga writeup diatas makanya aku gamau jelasin lagi.

## Pwning time!
Coba kita liat lagi ChildSmiHandler6.

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
    bug_here?((undefined8 *)local_68,(undefined8 *)(CommBuffer + 4),uVar8); // fungsi yang namanya diubah 
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
Sepertinya word pertama (4 byte) di CommBuffer dimasukkan switch case. Case pertama hanya menulis "Hello from SMM!" kedalam CommBuffer. Ini cara yang lumayan untuk tes juga komunikasi dengan fungsinya berhasil atau tidak. Case kedua hingga empat gak begitu penting. Yang kelima menarik, terdapat fungsi yang dipanggil (saya namakan bug_here?, karena gaada debug symbol), yang sepertinya mengimplementasi memcpy. Data di CommBuffer akan disalin ke local_68, yaitu array dengan ukuran 64 byte. Panjang yang dapat kita gunakan gaboleh lebih dari 199, tapi ini lebih dari cukup untuk ada buffer overflow dan melakukan ROP. Dengan ROP ini, kita bisa ambil flag yang dihardcode di address 0x7ff9ddf6

## Closing
Karena soal ini digunakan sebagai soal wargame di Dreamhack, sebaiknya aku gak menyediakan solverku. Writeup ini dan writeup sebelumnya sudah lebih dari cukup untuk menyelesaikan soal ini. Sebagai langkah awal, exploit dari soal corctf dapat disalin dengan fungsi ioremap diubah menjadi mmap. Dari situ, fokus untuk mencari cara interaksi dengan ChildSmiHandler6. Setelah bisa, eksploitasinya sangat gampang.

> Jawaban kuis: Gaada ASLR. Kita bisa tau alamat dari semua module / file efi dengan menambahkan debugcon di qemu. Ini sudah dijelaskan di writeup yang ditulis mebeim (player towerofhanoi) yang udah aku kasih sebelumnya.