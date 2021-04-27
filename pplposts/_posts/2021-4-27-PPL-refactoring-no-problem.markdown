---
layout: post
title:  "Refactoring? No problem!"
description: ""
permalink: /ppl/refactoring-no-problem/
---

_Untuk bahasa Indonesia, silakan klik link [ini](#bahasa-indonesia)_

## English
The project that I currently am working on at my PPL class is very interesting. One feature that was requested by the client is a method of exporting the current diagrams present in the web homepage, into a neat pdf file. The library we used to create the diagrams in called recharts, a library I have already covered in my first blog post.

A neat property of recharts diagrams in the fact that they are rendered as a svg object. This means, if we can access the svg data we can convert that svg data into a png, we then can use a library such as jsPDF to input the image into a pdf file. After a few hours of work, below was the resulting code.

![Error](/assets/images/PPL/Refactoring/1.png)

The code works perfectly, but it's a mess! This means we need to **Refactor** it!

### Refactor
Refactoring is the process of changing code that is already written, without changing the functionality. The goal is the resulting code **should** be cleaner, easier to read, and easier to maintain. When refactoring, a few points need to be remembered.

* The resulting code should be cleaner. If the resulting code is worse than the original, then you shouldn't have refactored it that way!
* No new functionality. Our goal here is so the code works just as before, no more and no less.
* All existing tests should still pass. If they do fail, expect the failing to arrive from different variable and function names instead of functionality failing.

[source](https://refactoring.guru/refactoring/how-to)

Alrighty then, let's begin!

### Current tests
Refactoring occurs as the third step in the TDD cycle. Meaning, our tests should be green right now! Let's check.

![Error](/assets/images/PPL/Refactoring/2.png)

Nice, we expect this to be the case after we refactor.

### Breaking down the code
Overall, this is what the code does

![Error](/assets/images/PPL/Refactoring/3-en.png)

Tasks like "write text" are done in two seperate places, and the svg->png code is all over the place. Instead, we can group these tasks together.

First, we create a function specifically for writing the text

![Error](/assets/images/PPL/Refactoring/4.png)

Then, we create three functions for the svg->png process.

![Error](/assets/images/PPL/Refactoring/5.png)

Now, we call the functions

![Error](/assets/images/PPL/Refactoring/6.png)

The reason we need the .then call is because this process should be done asynchronously. Loading assets like svg's and png's should be done in this way, even moreso since the pdf is created and downloaded to. The resulting code is as follows:

```jsx
const image2pdf  = (imageType: string, type: string, key: string) => {
  const imgWidth = 252;  
  const imgHeight = 156;  
  const pageWidth = 297;
  const pageHeight = 210;
  
  const marginX = (pageWidth - imgWidth) / 2;
  const marginY = 0;
  
  const doc = new jsPDF({orientation: "l", format:[pageWidth, pageHeight]});

  const writeTextToPDF = (doc: jsPDF) =>  {
    doc.setFontSize(14);
    doc.setFont("arial", "italic");
    if(key == "")
      doc.text("Keseluruhan kasus pada wilayah Depok", pageWidth/2, 160, {align:"center"});
    else
      doc.text(type + " " + key, pageWidth/2, 160, {align:"center"});

    doc.setFillColor(PIE_COLORS[0]);
    doc.rect(30, 170, 5, 5, 'F');
    doc.setFillColor(PIE_COLORS[1]);
    doc.rect(30, 180, 5, 5, 'F');
    doc.setFillColor(PIE_COLORS[2]);
    doc.rect(30, 190, 5, 5, 'F');

    doc.setFont("arial", "normal");
    doc.text("Kasus Positif", 40, 174, {align:"left"});
    doc.text("Kasus Negatif", 40, 184, {align:"left"});
    doc.text("Kasus Terduga", 40, 194, {align:"left"});
  }

  const svgToBlob = (svg: Element) => {
    svg.setAttribute("width", "952");
    svg.setAttribute("height", "589");
    svg.setAttribute("preserveAspectRatio", "xMidYMid meet");
    let svgURL = new XMLSerializer().serializeToString(svg);
    let svgBlob = new Blob([svgURL], { type: "image/svg+xml;charset=utf-8" });
    return svgBlob
  }

  const addImageToDoc = (img: CanvasImageSource, doc: jsPDF) => {
    let canvas = document.createElement('canvas');
    canvas.width = 952;
    canvas.height = 589;
    let context = canvas.getContext('2d')!;
    context.drawImage(img, 0, 0, context.canvas.width, context.canvas.height);
    let png = canvas.toDataURL('image/png', 1.0);
    doc.addImage(png, imageType, marginX, marginY, imgWidth, imgHeight, undefined, "SLOW");
  }

  const blobToImage = (blob: Blob) => {
    return new Promise<CanvasImageSource>(resolve => {
      const url = URL.createObjectURL(blob)
      let img = new Image()
      img.onload = () => {
        URL.revokeObjectURL(url)
        resolve(img)
      }
      img.src = url
    })
  }

  let svg: Element = document.getElementById(type)?.children[0]?.children[0].cloneNode(true)! as Element;
  let svgBlob = svgToBlob(svg);
  
  blobToImage(svgBlob).then(img => {
    addImageToDoc(img, doc);
    writeTextToPDF(doc);
    doc.save("bebas.pdf");
  });
};
```

Now you may be thinking, that the code doesn't seem that different. Well refactoring doesn't mean the code has to change much. Most of the code is required, and a change in structure is already good enough.

Let's see if the tests still pass

![Error](/assets/images/PPL/Refactoring/7.png)

Yup all good!

### Sources
* [Refactoring Guru](https://refactoring.guru/refactoring)

<br>
<br>
<br>


## Bahasa Indonesia
Projek yang sedang saya kerjakan pada mata kuliah PPL sangat menarik. Salah satu fitur yang diminta oleh _client_ merupakan metode untuk meng-*export* diagram yang sedang ditampilkan pada halaman beranda, kedalam sebuah file pdf. Library yang digunakan bernama recharts, sebuah library yang sudah saya dalami pada postingan blog pertama.

Salah satu sifat diagram recharts yang enak adalah diagram tersebut di-*render* sebagai svg. Oleh karena itu, jika kita bisa akses data svg tersebut kita bisa mengkonversikan data svg tersebut menjadi png. Lalu kita dapat menggunakan library seperti jsPDF untuk memasukkannya kedalam file pdf. Setelah beberapa jam bekerja, berikut hasil kodingan saya.

![Error](/assets/images/PPL/Refactoring/1.png)

Kodingan tersebut sudah berjalan, tapi kodingannya sangat jelek! Berarti kia mesti **Refactor** kodingan tersebut!

### Refactor
_Refactoring_ merupakan process mengubah kodingan yang sudah tertulis, tanpa mengubah fungsionalitasnya. Tujuan _refactoring_ adalah agar kodingan tersebut lebih bersih, mudah dibaca, dan mudah di-*maintain*. Ketika melakukan _refactoring_, beberapa poin tertentu mesti diingat.

* Hasil kodingan sebaiknya lebih bersih. Jika hasil kodingan tersebut lebih buruk dari yang awal, maka seharusnya tidak di-*refactor* seperti itu!
* Tidak ada fungsionalitas baru. Tujuan kita adalah agar kodingan tersebut bekerja seperti awal, tidak lebih dan tidak kurang.
* Semua tes yang sudah ada mesti lulus. Jika gagal, ekspektasi gagalnya karena berbeda nama variabel atau fungsi daripada gagal pada fungsionalitas.

[sumber](https://refactoring.guru/refactoring/how-to)

Oke, mari!

### Tes saat ini
_Refactoring_ terjadi pada langkah ketiga pada siklus TDD. Maka, tes kita sekarang seharusnya sudah _green_! Mari kita cek.

![Error](/assets/images/PPL/Refactoring/2.png)

Mantap, ekspektasi kita adalah hal ini tetap setelah kita melakukan _refactoring_

### Memecahkan kodingan
Secara umum, berikut hal yang dikerjakan oleh kodingan kita

![Error](/assets/images/PPL/Refactoring/3-id.png)

Tugas seperti "nulis teks" terjadi pada dua tempat yang berbeda, dan kodingan untuk mengubah svg menjadi png dimana-mana. Daripada begitu, kita bisa mengkelompokkan tugas ini.

Pertama, kita membuat fungsi khusus untuk menulis teks

![Error](/assets/images/PPL/Refactoring/4.png)

Lalu, kita membuat tiga fungsi untuk proses svg->png

![Error](/assets/images/PPL/Refactoring/5.png)

Sekarang, kita panggil fungsi tersebut

![Error](/assets/images/PPL/Refactoring/6.png)

Alasan kita memerlukan fungsi .then karena proses tersebut sebaiknya terjadi secara _asynchronous_. Memproses aset seperti svg dan png sebaiknya dilakukan dengan cara itu, apa lagi karena terdapat pdf yang dibuat dan diunduh. Hasil kodingan sebagai berikut.

```jsx
const image2pdf  = (imageType: string, type: string, key: string) => {
  const imgWidth = 252;  
  const imgHeight = 156;  
  const pageWidth = 297;
  const pageHeight = 210;
  
  const marginX = (pageWidth - imgWidth) / 2;
  const marginY = 0;
  
  const doc = new jsPDF({orientation: "l", format:[pageWidth, pageHeight]});

  const writeTextToPDF = (doc: jsPDF) =>  {
    doc.setFontSize(14);
    doc.setFont("arial", "italic");
    if(key == "")
      doc.text("Keseluruhan kasus pada wilayah Depok", pageWidth/2, 160, {align:"center"});
    else
      doc.text(type + " " + key, pageWidth/2, 160, {align:"center"});

    doc.setFillColor(PIE_COLORS[0]);
    doc.rect(30, 170, 5, 5, 'F');
    doc.setFillColor(PIE_COLORS[1]);
    doc.rect(30, 180, 5, 5, 'F');
    doc.setFillColor(PIE_COLORS[2]);
    doc.rect(30, 190, 5, 5, 'F');

    doc.setFont("arial", "normal");
    doc.text("Kasus Positif", 40, 174, {align:"left"});
    doc.text("Kasus Negatif", 40, 184, {align:"left"});
    doc.text("Kasus Terduga", 40, 194, {align:"left"});
  }

  const svgToBlob = (svg: Element) => {
    svg.setAttribute("width", "952");
    svg.setAttribute("height", "589");
    svg.setAttribute("preserveAspectRatio", "xMidYMid meet");
    let svgURL = new XMLSerializer().serializeToString(svg);
    let svgBlob = new Blob([svgURL], { type: "image/svg+xml;charset=utf-8" });
    return svgBlob
  }

  const addImageToDoc = (img: CanvasImageSource, doc: jsPDF) => {
    let canvas = document.createElement('canvas');
    canvas.width = 952;
    canvas.height = 589;
    let context = canvas.getContext('2d')!;
    context.drawImage(img, 0, 0, context.canvas.width, context.canvas.height);
    let png = canvas.toDataURL('image/png', 1.0);
    doc.addImage(png, imageType, marginX, marginY, imgWidth, imgHeight, undefined, "SLOW");
  }

  const blobToImage = (blob: Blob) => {
    return new Promise<CanvasImageSource>(resolve => {
      const url = URL.createObjectURL(blob)
      let img = new Image()
      img.onload = () => {
        URL.revokeObjectURL(url)
        resolve(img)
      }
      img.src = url
    })
  }

  let svg: Element = document.getElementById(type)?.children[0]?.children[0].cloneNode(true)! as Element;
  let svgBlob = svgToBlob(svg);
  
  blobToImage(svgBlob).then(img => {
    addImageToDoc(img, doc);
    writeTextToPDF(doc);
    doc.save("bebas.pdf");
  });
};
```

Mungkin Anda berpikir, kodingan tersebut tidak begitu berbeda. _Refactoring_ tidak berarti kodingan tersebut mesti sangat beda. Sebagian besar kodingan tersebut diperlukan, dan perubahan pada struktur sudah lumayan cukup.

Mari kita lihat apakah tes masih lulus

![Error](/assets/images/PPL/Refactoring/7.png)

Masih oke!

### Sumber
* [Refactoring Guru](https://refactoring.guru/refactoring)
