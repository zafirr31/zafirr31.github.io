---
layout: default
title:  "Google CTF 2019 Beginners Quest Write Up"
description: Super fun -zafirr
permalink: /posts/google-ctf-2019-beginners-quest-write-up/
categories: post
---

_Untuk bahasa Indonesia, silakan klik link [ini](#indonesian)_

## English

Google CTF was a blast, I am proud that I almost solve all the problems. The only ones I didnt solve during the CTF was CWO second flag, stop GAN second flag (though I could've solved it), and drive to the target. None of the main CTF problem were solved, as my team was busy during this time (besides me, but i didnt want to do it alone .-.) <br>
I'm not going to explain all the problems I solved, instead only my favorites


## 1. Crypto Caulingo (Cryptography)
All files used to solve this problem can be found [here](https://drive.google.com/drive/folders/1oaTMWEEujE2Tva8SBS08zeHpZ2eMG5lE?usp=sharing)

[Crypto Caulingo](https://ctftime.org/task/8823) was an [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) focused problem, where the public key (N,e) is givin aswell as the ciphertext (C). All of these numbers were included in the file msg.txt. Below is the contents of msg.txt. <br>
```
n:
17450892350509567071590987572582143158927907441748820483575144211411640241849663641180283816984167447652133133054833591585389505754635416604577584488321462013117163124742030681698693455489404696371546386866372290759608301392572928615767980244699473803730080008332364994345680261823712464595329369719516212105135055607592676087287980208987076052877442747436020751549591608244950255761481664468992126299001817410516694015560044888704699389291971764957871922598761298482950811618390145762835363357354812871474680543182075024126064364949000115542650091904557502192704672930197172086048687333172564520657739528469975770627

e:
65537

msg:
50fb0b3f17315f7dfa25378fa0b06c8d955fad0493365669bbaa524688128ee9099ab713a3369a5844bdd99a5db98f333ef55159d3025630c869216889be03120e3a4bd6553d7111c089220086092bcffc5e42f1004f9888f25892a7ca007e8ac6de9463da46f71af4c8a8f806bee92bf79a8121a7a34c3d564ac7f11b224dc090d97fdb427c10867ad177ec35525b513e40bef3b2ba3e6c97cb31d4fe3a6231fdb15643b84a1ce704838d8b99e5b0737e1fd30a9cc51786dcac07dcb9c0161fc754cda5380fdf3147eb4fbe49bc9821a0bcad98d6df9fbdf63cf7d7a5e4f6cbea4b683dfa965d0bd51f792047e393ddd7b7d99931c3ed1d033cebc91968d43f
```

Okay seems pretty straight forward, however, the modulus N is 600+ digits long, clear sign that the factors have a length of 1024 bits. Damn, it wont be possible to brute force. <br>
A file named project_dc.pdf was also included, which is a short description of how the encryption was done. Most of it isn't important, but point #3 is interesting.

![Error](/assets/images/Crypto-Caulingo-1.png)

Well this interesting, A and B are both under 1000, so a brute force of 1000\*1000 = 10^6 is very much possible. But what good would that do? Well to understand what im hinting at, knowing [Fermat Factorization](https://en.wikipedia.org/wiki/Fermat%27s_factorization_method) is required. I wont go into detail though, you can read it for yourself.

### The idea (Prepare for maths)
So we know that fermat factorization helps us to factor numbers whose factors have a very small difference. However, P and Q do not have any hints of having a small difference, besides the fact that there exists A\*P - B\*Q <= 10000. In order to be able to use this to our advantage, we need to know a number which is equal to P\*Q\*A\*B. Well that's easy, since P\*Q = N, P\*Q\*A\*B = N\*A\*B.

We know A and B is bruteforceable, so N\*A\*B is bruteforceable. Now all we have to do is apply fermat factorization until a valid P\*A and Q\*B is found.

### A problem
I ran the python program and took a break, because it took awhile, typical python. When I got back, to my surprise no factors were found. It really confused me on why that was the case, since the math looked	 OK already. Since it was already pretty late and I was desperate, I decided to increase the boundaries of A and B to 10000, and after a while it had found a valid factor.

```
P*A = 183418616017752024981052802086071392753555959441325309810851878945255982923202582076663525900047577536667835074425301476642198574207879059493416518541595424027660375448810757203294751343724397791635604962495192409599232522958909886259322349922299908840890831103514076739387653095174019512138856094160859860793142
Q*B = 183418616017752024981052802086071392753555959441325309810851878945255982923202582076663525900047577536667835074425301476642198574207879059493416518541595424027660375448810757203294751343724397791635604962495192409599232522958909886259322349922299908840890831103514076739387653095174019512138856094160859860774892
A = 397
B = 4856
```

Since we have P\*A and B\*Q, doing a simple gcd between N and those numbers give me a valid P and Q.

```
P = 151086174643947302290817794140091756798645765602409645643205831091644137498519425104335688550286307690830177161800083588667379385673705979813357923016141205953591742544325170678167010991535747769057335224460619777264606691069942245683132083955765987513089646708001710658474178826337742596489996782669571549253
Q = 115502906812186413716028212900548735990904256575141882752425616464266991765240920703188618324966988373216520827723741484031611192826120314542453727041306942082909556327966471790487878679927202639569020757238786152140574636623998668929044300958627146625246115304479897191050159379832505990011874114710868929959
```

The rest is basic RSA.

Flag: CTF{017d72f0b513e89830bccf5a36306ad944085a47}

<br>
<br>
<br>

## 2. Work Computer (Sandbox)
The problem uses the service here:

`nc readme.ctfcompetition.com 1337`

This was a fun jail-like problem, where we we're given a shell and nothing else. A simple 'ls -la' shows use that there are two files that have to be read, they most likely contain the flags.

![Error](/assets/images/Work-Computer-1.png)

The file README.flag has read privilage for owner, and ORME.flag has no privileges at all.


### Intended way
Now the intended way to solve this would be to see that the current directory has all privileges, so writing a file like a would be possible. If we did create a compressed file that included one of those files, we would get the privileges contents (say, by executing it). 

HOWEVER, I didnt do it like that, I did it my way >:D

### My way
I started by seeing what user i am, as well as my id
```
> id
uid=0 gid=0 euid=1338 groups=0
> whoami
whoami: unknown uid 1338
```
Ok i should be user 1338, weird why its like that.

Then i looked into /bin. /bin is basically a folder that contains all the default binaries that can be used. Here is the contents of /bin:

```
total 808
drwxr-xr-x    2 65534    65534         4096 Jun 13 14:28 .
drwxr-xr-x   20 0        0             4096 Jun 13 14:28 ..
lrwxrwxrwx    1 65534    65534           12 May  9  2019 arch -> /bin/busybox
-rwxr-xr-x    1 65534    65534       796240 Jan 24  2019 busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 chgrp -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 chown -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 conspy -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 date -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 df -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 dmesg -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 dnsdomainname -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 dumpkmap -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 echo -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 false -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 fdflush -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 fsync -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 getopt -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 hostname -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 ionice -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 iostat -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 ipcalc -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 kill -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 login -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 ls -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 lzop -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 makemime -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 mkdir -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 mknod -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 mktemp -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 mount -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 mountpoint -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 mpstat -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 netstat -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 nice -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 pidof -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 ping -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 ping6 -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 pipe_progress -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 printenv -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 ps -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 pwd -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 reformime -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 rm -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 rmdir -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 run-parts -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 setpriv -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 setserial -> /bin/busybox
-r-sr-xr-x    1 1338     1338         19936 Jun 13 12:48 shell
lrwxrwxrwx    1 65534    65534           12 May  9  2019 sleep -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 stat -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 stty -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 sync -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 tar -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 true -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 umount -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 uname -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 usleep -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 watch -> /bin/busybox
```

The '->' symbol basically states that those binaries are a symbolic link to /bin/busybox. Symbolic links are kindof like pointers, the binary X points to /bin/busybox where busybox has a binary named X too. You can learn more about symbolic links [here.](https://www.cyberciti.biz/faq/creating-soft-link-or-symbolic-link/)

So what's so special about busybox? According to the [busybox website](https://busybox.net/about.html), busybox is an executable file that contains other executable files, this could be useful. The problem is when I try to run the busybox executable, I get the error:

```
> busybox
busybox can not be called for alien reasons.
```

Well that's not good, how can we get around this? If we look carefully, there is a setpriv binary that we can use in /bin. To be honest I didn't know what setpriv actually does, heck I still don't know now, but all I know is running `setpriv busybox` allows me to run it.

### What I should have done (part 2)
Now that i have access to busybox, I should have thought to do chmod 777 on README.flag and ORME.flag, but ofcourse I was dumb and didn't do that.

Instead, I did something probably unintended

### What I did
So after fiddleing around with setpriv for a while, I figured out that doing `setpriv --nnp` allowed me to become uid 0. In this challenge, uid 0 isnt root :o, so it seemed like a wall at first. However, I found a cool folder by chance, in which uid 0 owned it.

![Error](/assets/images/Work-Computer-2.png)

It too had the flags in it, so i just tried a regular 'cat'. It worked .-.

```
> setpriv --nnp busybox cat /srv/challenge_setup/README.flag
CTF{4ll_D474_5h4ll_B3_Fr33}
> setpriv --nnp busybox cat /srv/challenge_setup/ORME.flag         
CTF{Th3r3_1s_4lw4y5_4N07h3r_W4y}
```

¯\\\_(ツ)\_/¯

<br>
<br>
<br>
<br>
<br>

## Indonesian

Google CTF tahun ini luar biasa seru, aku bangga bisa menyelesaikan hampir semua soal. Hanya flag _CWO_ kedua, _stop GAN_ kedua (seharusnya bisa solve), dan _drive to the target_ yang tidak berhasil aku solve. Tidak ada soal dari CTF utama yang berhasil saya solve, sebab timku sibuk saat lombanya berlangsung (kecuali aku, tapi aku gak mau solve sendirian)<br>
Aku tidak akan menjelaskan semua soal yang berhasil saya solve, tetapi hanya soal favoritku.

## 1. Crypto Caulingo (Kriptografi)
Semua file yang saya gunakan untuk menyelesaikan soal ini terdapat [disini](https://drive.google.com/drive/folders/1oaTMWEEujE2Tva8SBS08zeHpZ2eMG5lE?usp=sharing)

[Crypto Caulingo](https://ctftime.org/task/8823) merupakan soal yang berdasar [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)), dimana _public key_ (N,e) dan _ciphertext_ diberikan. Angka-angka tersebut diberikan di dalam file msg.txt. Berikut isi dari msg.txt.

```
n:
17450892350509567071590987572582143158927907441748820483575144211411640241849663641180283816984167447652133133054833591585389505754635416604577584488321462013117163124742030681698693455489404696371546386866372290759608301392572928615767980244699473803730080008332364994345680261823712464595329369719516212105135055607592676087287980208987076052877442747436020751549591608244950255761481664468992126299001817410516694015560044888704699389291971764957871922598761298482950811618390145762835363357354812871474680543182075024126064364949000115542650091904557502192704672930197172086048687333172564520657739528469975770627

e:
65537

msg:
50fb0b3f17315f7dfa25378fa0b06c8d955fad0493365669bbaa524688128ee9099ab713a3369a5844bdd99a5db98f333ef55159d3025630c869216889be03120e3a4bd6553d7111c089220086092bcffc5e42f1004f9888f25892a7ca007e8ac6de9463da46f71af4c8a8f806bee92bf79a8121a7a34c3d564ac7f11b224dc090d97fdb427c10867ad177ec35525b513e40bef3b2ba3e6c97cb31d4fe3a6231fdb15643b84a1ce704838d8b99e5b0737e1fd30a9cc51786dcac07dcb9c0161fc754cda5380fdf3147eb4fbe49bc9821a0bcad98d6df9fbdf63cf7d7a5e4f6cbea4b683dfa965d0bd51f792047e393ddd7b7d99931c3ed1d033cebc91968d43f
```

Terlihat sangat jelas, tetapi modulus N yang diberi merupakan angka dengan 600+ digit, tanda jelas bahwa faktor-faktornya memiliki panjang 1024 bit. Sial, sepertinya tidak bisa dibruteforce.<br>
Selain itu, diberi juga file project_dc.pdf, yang berisi penjelasan tentang cara enckripsi tersebut dilakukan. Sebagian besar tidak penting, tapi bagian #3 menarik.

![Error](/assets/images/Crypto-Caulingo-1.png)

Sangat menarik, A dan B dibawah 1000, jadi bruteforce 1000\*1000 = 10^6 memungkinkan. Tapi emang berguna? Agar lebih mengerti apa yang saya mengintai, ilmu tentang [_Fermat Factorization_](https://en.wikipedia.org/wiki/Fermat%27s_factorization_method) dibutuhkan. Aku tidak akan menjelaskan dengan detail, anda bisa baca sendiri.

### Idenya (Siap-siap akan ada matematika)
Jadi kita tahu _fermat factorization_ membantu untuk memfaktorkan angka yang selisih faktornya kecil. Akan tetapi, P dan Q belum tentu memiliki selisih yang kecil, selain bahwa terdapat A\*P - B\*Q <= 10000. Agar dapat menguntungkan kita, kita perlu tahu angka yang sama dengan P\*Q\*A\*B. Ya itu kan mudah, oleh karena P\*Q = N, P\*Q\*A\*B = N\*A\*B

Kita tahu bahwa A dan B dapat dibruteforce, jadi N\*A\*B dapat dibruteforce. Nah sekarang kita tinggal menggunakan _fermat factorization_ sampai P\*A dan Q\*B yang valid ditemukan.

### Sebuah masalah
Aku jalanin program pythonnya dan kemudian istirahat, karena membutuhkan waktu agak lama, biasa python. Ketika aku kembali, ternyata tidak ada faktor yang didapatkan. Itu sangat membingungkan untuk aku, karena rumus yang aku dapat terlihat OK. Karena udah agak kemalaman dan aku mulai putus asa, aku memilih untuk meningkatkan batas-batas A dan B ke 10000, beberapa waktu kemudian ditemukan sebuah faktor.

```
P*A = 183418616017752024981052802086071392753555959441325309810851878945255982923202582076663525900047577536667835074425301476642198574207879059493416518541595424027660375448810757203294751343724397791635604962495192409599232522958909886259322349922299908840890831103514076739387653095174019512138856094160859860793142
Q*B = 183418616017752024981052802086071392753555959441325309810851878945255982923202582076663525900047577536667835074425301476642198574207879059493416518541595424027660375448810757203294751343724397791635604962495192409599232522958909886259322349922299908840890831103514076739387653095174019512138856094160859860774892
A = 397
B = 4856
```

Nah karena sudah punya P\*A dan Q\*B, mencari gcd angka tersebut dengan modulus N akan menghasilkan P dan Q yang valid.

```
P = 151086174643947302290817794140091756798645765602409645643205831091644137498519425104335688550286307690830177161800083588667379385673705979813357923016141205953591742544325170678167010991535747769057335224460619777264606691069942245683132083955765987513089646708001710658474178826337742596489996782669571549253
Q = 115502906812186413716028212900548735990904256575141882752425616464266991765240920703188618324966988373216520827723741484031611192826120314542453727041306942082909556327966471790487878679927202639569020757238786152140574636623998668929044300958627146625246115304479897191050159379832505990011874114710868929959
```

Sisanya RSA biasa.

Flag: CTF{017d72f0b513e89830bccf5a36306ad944085a47}

<br>
<br>
<br>

## 2. Work Computer (Sandbox)
Soal ini menggunakan service berikut:

`nc readme.ctfcompetition.com 1337`

Soal ini merupakan soal seru yang _jail-like_, dimana kita hanya diberi suatu shell. Menjalankan 'ls -la' menunjukkan bahwa terdapat dua file yang mesti dibaca, dan kemungkinan besar kedua file tersebut berisi flag.

![Error](/assets/images/Work-Computer-1.png)

File README.flag mempunyai hak membaca untuk _owner_, dan file ORME.flag tidak mempunyai hak apapun.

### Cara semestinya
Nah cara yang semestinya dilakukan untuk menyelesaikan soal ini adalah sadar bahwa folder sekarang memunyai semua hak, jadi menulis suatu file dapat dilakukan. Jika kita kompres salah satu file tersebut, kita bisa mendapatkan isi filenya (misal, menjalankan file terkompresnya).

### Caraku
Aku mulai dengan melihat aku sekarang user siapa, dan juga idku.

```
> id
uid=0 gid=0 euid=1338 groups=0
> whoami
whoami: unknown uid 1338
```

Sepertinya aku user 1338, aneh kenapa kok begitu.

Kemudian aku melihat kedalam folder /bin. /bin secara singkat merupakan folder yang berisi semua _binaries_ default yang saya dapat gunakan. Berikut isi /bin:

```
total 808
drwxr-xr-x    2 65534    65534         4096 Jun 13 14:28 .
drwxr-xr-x   20 0        0             4096 Jun 13 14:28 ..
lrwxrwxrwx    1 65534    65534           12 May  9  2019 arch -> /bin/busybox
-rwxr-xr-x    1 65534    65534       796240 Jan 24  2019 busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 chgrp -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 chown -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 conspy -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 date -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 df -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 dmesg -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 dnsdomainname -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 dumpkmap -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 echo -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 false -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 fdflush -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 fsync -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 getopt -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 hostname -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 ionice -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 iostat -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 ipcalc -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 kill -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 login -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 ls -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 lzop -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 makemime -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 mkdir -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 mknod -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 mktemp -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 mount -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 mountpoint -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 mpstat -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 netstat -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 nice -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 pidof -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 ping -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 ping6 -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 pipe_progress -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 printenv -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 ps -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 pwd -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 reformime -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 rm -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 rmdir -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 run-parts -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 setpriv -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 setserial -> /bin/busybox
-r-sr-xr-x    1 1338     1338         19936 Jun 13 12:48 shell
lrwxrwxrwx    1 65534    65534           12 May  9  2019 sleep -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 stat -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 stty -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 sync -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 tar -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 true -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 umount -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 uname -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 usleep -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9  2019 watch -> /bin/busybox
```

Simbol '->' secara singkat menyatakan bahwa _binary_ tersebut merupakan suatu link simbolik ke /bin/busybox. Link simbolik dapat dibilang suatu _pointer_, misal file X menunjuk ke /bin/busybox dimana busybox juga memiliki file yang bernama X juga. Anda dapat pelajari lebih lanjut tentang link simbolik [disini](https://www.cyberciti.biz/faq/creating-soft-link-or-symbolic-link/)

Jadi apa istimewanya busybox? Menurut [web busybox](https://busybox.net/about.html), busybox merupakan _binary_ yang mengandung _binary_ lain di dalamnya, ini bisa jadi sangat berguna. Akan tetapi ada masalah ketika aku mencoba menjalankan busybox, muncul error:

```
> busybox
busybox can not be called for alien reasons.
```

Yah itu gak bagus, bagaimana kita dapat melewati ini? Jika kita liat baik-baik, terdapat _binary_ setpriv yang dapat kita gunakan didalam /bin. Jujur dulu aku gak begitu mengerti setpriv itu untuk apa, sekarang pun masih belum begitu mengerti, tapi yang penting menjalankan `setpriv busybox` mengizinkan aku untuk menjalankannya.

### Apa yang seharusnya aku lakukan (part 2)
Nah sekarang karena aku sudah bisa menjalankan busybox, seharusnya saya lakukan chmod 777 ke README.flag dan ORME.flag, tapi ya aku bodoh dan tidak melakukan itu.

Melainkan, aku melakukan sesuatu yang seharusnya tidak dilakukan

### Apa yang aku lakukan
Jadi setelah bermain dengan setpriv untuk sebentar, aku nyadar bahwa melakukan `setpriv --nnp` mengizinkan aku untuk menjadi uid 0. Anehnya dalam soal ini uid 0 bukan root :o, jadi aku kita buntu awalnya. Akan tetapi, aku menemukan suatu folder keren secara random, dimana uid 0 pemiliknya.

![Error](/assets/images/Work-Computer-2.png)

Di folder ini juga ada kedua flag, jadi aku coba 'cat' biasa, bisa .-.

```
> setpriv --nnp busybox cat /srv/challenge_setup/README.flag
CTF{4ll_D474_5h4ll_B3_Fr33}
> setpriv --nnp busybox cat /srv/challenge_setup/ORME.flag         
CTF{Th3r3_1s_4lw4y5_4N07h3r_W4y}
```

¯\\\_(ツ)\_/¯