---
layout: post
author: zafirr
title:  "The Lenstra Elliptic Curve Method of Factorization"
description: Really cool algorithm
date: 2021-02-23
last_modified_at: 2021-02-23
categories: research
lang: id
tags:
    - crypto
---

# Indonesian
Bulan ini aku mau santai, gak nulis tentang CTF. Jadi daripada writeup aku pengen teliti lebih dalam salah satu alat yang sering aku gunakan pada CTF, khususnya untuk soal crypto. Alatnya adalah [kalkulator faktorisasi integer oleh Dario Alpern](https://www.alpertron.com.ar/ECM.HTM). Kalkulator ini menggunakan dua metode yang berbeda untuk melakukan faktorisasi, yang pertama adalah [Metode Elliptic Curve (ECM)](https://en.wikipedia.org/wiki/Lenstra_elliptic-curve_factorization), dan yang kedua adalah [Kuadratik Sieve (SIQS)](https://en.wikipedia.org/wiki/Quadratic_sieve).

Aku milih algoritma ECM untuk diteliti, dan pada postingan ini aku juga punya kodingan python yang dapat digunakan, tapi mungkin gak begitu cepat maupun rapi.

## Gimana cara kerjanya?
Algoritmanya sendiri tidak begitu sulit, jadi aku  kutip aja [Wikipedia](https://en.wikipedia.org/wiki/Lenstra_elliptic-curve_factorization) sebagai sumber aku.

### Bagian 1: Elliptic curve
Yang pertama yang mesti kita lakukan adalah membuat suatu elliptic curve yang random. Apa itu elliptic curve? Elliptic cure merupakan kurva yang memenuhi persamaan berikut:

`y**2 = x**3 + a*x + b`

Dengan a dan b bilangan riil. Walaupun terdengar mirip, elliptic curve tidak memiliki hubungan yang kuat dengan ellips (AFAIK).

Menurut wikipedia, kita dapat malakukan ini dengan pertama memilih titik acak (x0, y0) dan angka acak untuk konstanta 'a'. Setelah itu konstanta 'b' dihitung dengan cara berikut:

`b = y**2 - x**3 - a*x`

Cara ini merupakan cara yang mudah untuk mendapatkan elliptic curve dan memastikan sudah ada titik yang berada padanya. 

<br>

Agar algoritma ini berhasil, kita sebenarnya memerlukan elliptic curve dalam suatu finite field. Anda dapat membaca lebih lanjut tentang finite field [disini](https://en.wikipedia.org/wiki/Finite_field). Lebih tepatnya, asumsikan kita ingin mencari faktor dari suatu bilangan bulat N. Berarti finite field yang kita ingin gunakan merupakan Galois field N (GF(N)). Berarti elliptic curve kita berubah jadi berikut:

`y**2 ≡ x**3 + a*x + b (mod N)`

### Bagian 2: Penjumlahan titik pada elliptic curve
Salah satu bagian terbesar dari algoritma ini adalah penggunaaan penjumlahan dua titik. Orang jago sudah memikirkan tentang ini, dan mereka sudah mendefinisikan secara tepat cara melakukan penjumlahan dua titik pada elliptic curve. Katakan kita punya 2 titik pada elliptic curve kita, P (xP, yP) dan Q (xQ, yQ) serta hasil yang diinginkan merupakan titik R (xR, yR). Untuk menghitung P + Q = R, terlebih dahulu kita perlu menghitung suatu koeffisien λ. Menurut sumber [ini](https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Point_addition), terdapat 2 kemungkinan, antara P dan Q merupakan titik yang berbeda atau merupakan titik yang sama. Jika mereka titik yang **berbeda**, λ dihitung dengan cara berikut:

`λ = (yQ - yP) / (xQ - xP)`

Itu untuk elliptic curve yang bukan berada pada finite field. Jika pada finite field, λ dihitung dengan cara berikut:

`λ ≡ (yQ - yP) * inverse_modulo(xQ - xP, N) (mod N)`

Hal ini disebabkan cara [operasi pembagian dilakukan pada finite field](https://en.wikipedia.org/wiki/Finite_field_arithmetic#:~:text=Division%20is%20multiplication%20by%20the,division%20is%20the%20identity%20function.). Jika P dan Q merupakan titik yang **sama**, λ dihitung dengan cara berikut:

`λ = (3*xP**2 + a) / yP`

Dan untuk finite field:

`λ ≡ (3*xP**2 + a) * inverse_modulo(yP, N) (mod N)`

Setelah menghitung lambda, xR dan yR dihitung dengan cara berikut:

`xR = λ**2 - xP - xQ`  ;   `yR = λ(xP-xR) - yP`

### Bagian 3: Perkalian skalar pada elliptic curve
Untuk perkalian dengan skalar, kita dapat melakukan penjumlahan titik dan penggandaan untuk mendapatkan perkalian yang O(log k) yang efisien, untuk suatu skalar k. Metode ini mirip dengan [metode pemangkatan cepat](https://en.wikipedia.org/wiki/Modular_exponentiation#Right-to-left_binary_method), jadi saya tidak akan menjelaskan cara kerjanya.

### Bagian 4: Bagian ECM
Karena kita sudah memiliki suatu elliptic curve, suatu titik acak P dan sudah mendefinisikan penjumlahan dua titik, kita perlu menghitung (B!)\*P, dengan B tidak terlalu besar. (B!)\*P dapat dihitung secara efisien dengan menghitung terlebih dahulu 2\*P, setelah itu 3\*(2\*P), kemudian 4\*(3\*(2\*P)), dst. Pada saat proses ini berlangsung, salah satu dari dua hal akan terjadi:
* Titik yang tidak dapat dicari inverse modulonya ditemukan, hal ini berarti gcd(v, n) != 1 untuk suatu v. Pada kasus ini gcd(v, n) bisa saja sama dengan n, dalam kasus itu kita hanya perlu ulang dari awal lagi. Akan tetapi jika bukan n maka kita telah menemukan salah satu faktor.
* Semua titik berhasil dicari inverse modulonya, maka kita ulang lagi saja dari awal dengan kurva acak yang baru.

Ya begitu aja sih. Lumayan simpel, jadi dibawah ini kodingan dalam python. Pada kodingan tersebut terdapat suatu semiprime yang terdiri dari 2 prima 64-bit. Kodingan saya memerlukan sekitar 1 menit untuk faktorisasinya.

![Error](/assets/images/Lenstra_ECM/1.png)

**CATATAN: KODINGAN INI TIDAK SIAP UNTUK DIGUNAKAN PADA PRODUCTION. JANGAN GUNAKAN PADA IMPLEMENTASI KRIPTOGRAFI**

```py
import random
import sys
import time
import math

from Crypto.Util.number import isPrime

class EllipticCurveFiniteField:
    
    def __init__(self, x0, y0, a, n):
        self.a = a
        self.b = y0**2 - x0**3 - a*x0
        self.n = n
        self.O = "Origin"
    
    def isValidPoint(self, x, y) -> bool:
        return (y**2 % self.n) == (x**3 + self.a*x + self.b) % self.n
    
    def __eq__(self, other):
        return self.a == other.a and self.b == other.b and self.n == other.n
    
    def __str__(self):
        return f'y**2 = x**3 + {self.a}*x + {self.b} (mod {self.n})'

class EllipticCurvePoint:

    def __init__(self, curve, x, y):
        
        self.curve = curve
        self.x = x
        self.y = y
        assert curve.isValidPoint(x, y), "Point is not on curve"
    
    def __eq__(self, other):
        return self.curve == other.curve and self.x == other.x and self.y == other.y

    def __add__(self, other):
        assert self.curve == other.curve
        # Assume self and other is P and Q, result is R
        # Algorithm: https://en.wikipedia.org/wiki/Elliptic_curve#The_group_law
        if(self == other):
            divisor = inverse_mod(2*self.y, self.curve.n)
            s = (3*self.x**2 + self.curve.a) * divisor % self.curve.n
        else:
            divisor = inverse_mod(self.x - other.x, self.curve.n)
            s = (self.y - other.y) * divisor % self.curve.n
        xR = (s**2 - self.x - other.x) % self.curve.n
        yR = (s*(self.x- xR) - self.y) % self.curve.n
        return EllipticCurvePoint(self.curve, xR, yR)

    def __mul__(self, k):
        assert k >= 0
        if(k == 0):
            return self.curve.origin
        
        base = EllipticCurvePoint(self.curve, self.x, self.y)
        res = EllipticCurvePoint(self.curve, self.x, self.y)
        while(not k & 1):
            res += res
            base += base
            k >>= 1
        k >>= 1
        base = base + base
        while(k > 0):
            if(k & 1):
                res += base
            base += base
            k >>= 1
        return res

    def __rmul__(self, k):
        return self.__mul__(k)

    def __str__(self):
        return f"({self.x}, {self.y}) on curve {self.curve}"

def gcd(a, b):
    '''Get GCD of a and b'''
    if(b == 0):
        return a
    return gcd(b, a % b)

def egcd(a, b):
    if(b == 0):
        return a, 1, 0
    
    temp_gcd, temp_x, temp_y = egcd(b, a % b)

    y = temp_x - (a // b)*temp_y
    x = temp_y

    return temp_gcd, x, y

def inverse_mod(a, n):
    '''Get Multiplicative modular inverse of a mod n'''
    if gcd(a, n) != 1:
        raise NoModularInverse(gcd(a, n))

    _gcd, x, _y = egcd(a, n)

    return x % n


def generate_random_point_and_curve(n):
    a = random.randint(1, n)
    x0 = random.randint(1, n)
    y0 = random.randint(1, n)
    
    curve = EllipticCurveFiniteField(x0, y0, a, n)
    point = EllipticCurvePoint(curve, x0, y0)
    return point, curve

class NoModularInverse(Exception):
    pass

sys.setrecursionlimit(4000)
to_factor = 142207032646172885627320863923329208329
cnt = 1
curve_count = 1
factor_list = []
B = 2000
start_time = time.time()
while True:
    point, curve = generate_random_point_and_curve(to_factor)
    print(f"curve count: {curve_count}")
    curve_count += 1
    for i in range(1, B+1):
        try:
            point = i * point
        except NoModularInverse as e:
            factor = int(str(e))
            if(gcd(factor, to_factor) != to_factor):
                print(f"Factor {cnt}: {factor}")
                cnt += 1
                to_factor //= int(str(e))
                factor_list.append(factor)
                break
    if(isPrime(to_factor)):
        break
print(f"Last Factor: {to_factor}")
factor_list.append(to_factor)

print(f"All Factors: {factor_list}")
print("--- %s seconds ---" % (time.time() - start_time))
```
