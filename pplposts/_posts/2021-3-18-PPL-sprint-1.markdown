---
layout: post
title:  "Creating charts with React JS"
description: "Using recharts library"
permalink: /ppl/ppl-sprint-1/
---

![Error](https://res.cloudinary.com/practicaldev/image/fetch/s--xcUTA8ET--/c_imagga_scale,f_auto,fl_progressive,h_720,q_auto,w_1280/https://dev-to-uploads.s3.amazonaws.com/i/4fauvcmllrgmni7bklfp.png)

_Untuk bahasa Indonesia, silakan klik link [ini](#bahasa-indonesia)_

## English
With the rise in popularity for Frontend Development, many programmers look towards Javascript as thier main development language. This has given rise to many versatile frameworks, one of the most famous being the [React JS](https://reactjs.org/) framework. It's integration with npm and webpack allows ease of use with public javascript libraries found in the [npm registry](https://www.npmjs.com/).

These past two weeks, I had my first Sprint for CSCM603228 (Projek Perangkat Lunak). The application that is current being developed in this class is called TBCare, which is an application to help in the listing of [Tuberculosis](https://en.wikipedia.org/wiki/Tuberculosis) cases across Depok, West Java.

In this sprint, I was given the task to improve the diagrams located at the homepage for administrators. Here's what they look like:

![Error](/assets/images/PPL/Sprint_1/1.png)

![Error](/assets/images/PPL/Sprint_1/2.png)


*This sprint, I refactored some of the code, adding the customization to the diagram you see in the screenshot. Yay me!

The library that was used to create those diagrams is called [recharts](https://recharts.org/), an open-source javascript project to create diagrams with the React JS framework. I decided to dig deeper into how its works, and in this blog post I will explain how to use it. From installation, simple usage, all the way until testing. Let's go!

<br>

### Installing Recharts
To install recharts for use in our web project, we have a couple things we can do.

1. Use a package manager<br>
    As React is integrated with webpack, any mainstream package manager will do. 
    ```bash
    npm install recharts
    # or
    yarn add recharts 
    ```
2. Directly include it into pages that require it<br>
    To do so, just add these few lines of html into the html file that requires it
    ```html
    <script src="https://unpkg.com/react/umd/react.production.min.js"></script>
    <script src="https://unpkg.com/react-dom/umd/react-dom.production.min.js"></script>
    <script src="https://unpkg.com/prop-types/prop-types.min.js"></script>
    <script src="https://unpkg.com/recharts/umd/Recharts.min.js"></script>
    ```
    The library can then be found in the window.Recharts variable

### Basic usage
Let's assume we have the following data:

| Gender | Positive Cases | Negative Cases | 
|-------|--------|--------|
| Men | 46 | 732 |
| Women | 55 | 645 |

And we wanted to show this data as a Bar Chart. With recharts, this is very simple, below is an example of how to do it:

```jsx
import {BarChart, Bar} from 'recharts'

const data = [
    {
      name: 'Positive Cases',
      men: 46,
      women: 55,
    },
    {
      name: 'Negative Cases',
      men: 732,
      women: 645,
    },
  ];

function App() {
  return (
    <BarChart width={500} height={300} data={data}>
      <Bar dataKey="men" fill="#8884d8" />      // note the dataKeys and how 
      <Bar dataKey="women" fill="#82ca9d" />    // they relate to the json array!
    </BarChart>
  );
}

export default App;
```

The most important thing is the array of json data that is passed to the component, recharts handles everything else!

![Error](/assets/images/PPL/Sprint_1/3.png)

We may want to add an XAxis and YAxis, as it is important to represent our data. Recharts has a component for that too!

```jsx
import {BarChart, XAxis, YAxis, Bar} from 'recharts'

.
.
.

function App() {
  return (
    <BarChart width={500} height={300} data={data}>
      <XAxis dataKey="name" />      // Note the dataKey!
      <YAxis />
      <Bar dataKey="men" fill="#8884d8" />
      <Bar dataKey="women" fill="#82ca9d" />
    </BarChart>
  );
}
```

![Error](/assets/images/PPL/Sprint_1/4.png)

Hmm, this is good, but we can't tell which is men and which is women. Let's add a legend!

```jsx
import {BarChart, XAxis, YAxis, Legend, Bar} from 'recharts'

.
.
.

function App() {
  return (
    <BarChart width={500} height={300} data={data}>
      <XAxis dataKey="name" />
      <YAxis />
      <Legend />    // This is all we need to add!
      <Bar dataKey="men" fill="#8884d8" />
      <Bar dataKey="women" fill="#82ca9d" />
    </BarChart>
  );
}
```

![Error](/assets/images/PPL/Sprint_1/5.png)

This is actually fine already. But maybe we want to add a quality of life addition? Let's add a tooltip! A tooltip is just a nice detail that shows the amount when the bar is hovered over. Adding it is REALLY simple.

```jsx
import {BarChart, XAxis, YAxis, Legend, Tooltip, Bar} from 'recharts'

.
.
.

function App() {
  return (
    <BarChart width={500} height={300} data={data}>
      <XAxis dataKey="name" />
      <YAxis />
      <Legend />
      <Tooltip />   // Just like adding the legend!
      <Bar dataKey="men" fill="#8884d8" />
      <Bar dataKey="women" fill="#82ca9d" />
    </BarChart>
  );
}
```

![Error](/assets/images/PPL/Sprint_1/6.png)

![Error](/assets/images/PPL/Sprint_1/7.png)

Now that looks really good! For now, that's enough for me. The components and props that are given by the recharts library are very vast, and allow for alot of customization. Feel free to read their documentation [here](https://recharts.org/en-US/api)

<br>

As a bonus, here's the some random data on attendence to a random event, represented as a Line Chart!

{% raw %}
```jsx
import {CartesianGrid, Legend, Line, LineChart, Tooltip, XAxis, YAxis} from 'recharts'

const data = [
    {
      name: '2016',
      men: 360,
      women: 423,
    },
    {
      name: '2017',
      men: 778,
      women: 825,
    },
    {
      name: '2018',
      men: 912,
      women: 887,
    },
    {
      name: '2019',
      men: 890,
      women: 767,
    },
    {
      name: '2020',
      men: 791,
      women: 727,
    },   
  ];

function App() {
  return (
        <>
            <h2 style={{ fontFamily: 'Courier New' }} >Attendance to Zafir Festival, by gender</h2>
            <LineChart width={500} height={450} data={data}>
                <XAxis dataKey="name" />
                <YAxis />
                <Tooltip />
                <Legend />
                <CartesianGrid />
                <Line type="monotone" dataKey="men" stroke="#0000FF"/>
                <Line type="monotone" dataKey="women" stroke="#9ACD32"/>
            </LineChart>
        </>
  );
}

export default App;
```
{% endraw %}

![Error](/assets/images/PPL/Sprint_1/8.png)

<br>

### Setting up tests
Like all good software developers, following the Test Driven Development Paradigm is very well respected. Even for frontend development, we can create unit tests for the components we have/will have made.

There are many testing libraries to use, but in this blog post I will be using [enzyme](https://enzymejs.github.io/enzyme/).

<br>

First, we need to install enzyme. This can be done using npm.
```bash
npm install enzyme
# or
yarn add enzyme 
```

Enzyme also requires an extra library, which is the adapter library. Fit the version with the version of react that is your project.
```bash
npm install enzyme-adapter-react-16     # Note the version!
# or
yarn add enzyme-adapter-react-16    # Note the version!
```

We also need the chai library, which is a library for test assertions.
```bash
npm install chai
# or
yarn add chai
```

There's one last step we need to do. In a basic react project, there is a file called `setupTests.js`, in there add these lines of code:
```js
import { configure } from 'enzyme';
import Adapter from 'enzyme-adapter-react-16';  //Note the version!

configure({ adapter: new Adapter() });
```

Ok now we're ready to create tests!

<br>

### Creating tests
What is there to test? Well since we have a component that renders some other components, we can test if those components really get rendered/not! Enzyme also gives us the option to fully render the components, or just do shallow rendering. Since this blog post is getting kind of long, I will show only shallow rendering.

Let's use the previous code with the BarChart. In the code, we would expect that our component (App) will render one BarChart, and two Bars. Let's import what we need first:

```jsx
import { expect } from 'chai';
import { shallow } from 'enzyme';
import {BarChart, Bar} from 'recharts'

import App from './App'
```

Since the component we want to test is called App, we will "describe" that component:

```jsx
import { expect } from 'chai';
import { shallow } from 'enzyme';
import {BarChart, XAxis, YAxis, Tooltip, Legend, Bar} from 'recharts'

import App from './App'

describe('<App />', () => {
});
```

Now we need to add the unit tests into that describe function. We can do that using the `it` function. The parameters to the `it` function is a brief description on what is expected in the test, and the test function itself. In other programming languages testing libraries (in django or spring), the description is usually embedded into the name of the function. In this case, it's just a regular string.

```jsx

import { expect } from 'chai';
import { shallow } from 'enzyme';
import {BarChart, XAxis, YAxis, Tooltip, Legend, Bar} from 'recharts'

import App from './App'

describe('<App />', () => {
   it('renders a BarChart', () => {
    const wrapper = shallow(<App />);
    expect(wrapper.find(BarChart)).to.have.lengthOf(1);
   });

   it('renders two Bars', () => {
    const wrapper = shallow(<App />);
    expect(wrapper.find(Bar)).to.have.lengthOf(2);
   });
});
```

Basically, what the test function doing is it's going to shallowly render the App component, then "find" how many BarCharts / Bars are in that component. Then it compares it with the expected value.

To run these tests, all we need to do is run the `npm test` command.

![Error](/assets/images/PPL/Sprint_1/9.png)

![Error](/assets/images/PPL/Sprint_1/10.png)

Success!

<br>

### Closing Statements
Recharts is a wonderful javascript library to create diagrams. In this modern age, where data science is extremely important for businesses, libraries to create diagrams automatically given data is amazing. For larger projects, its easy integration with testing libraries allows recharts diagrams to be tested easily and very quickly.

Sources:
* [React](https://reactjs.org/)
* [Recharts](https://recharts.org/en-US)
* [Enzyme](https://enzymejs.github.io/enzyme/)
* [Chai](https://www.chaijs.com/)

<br>
<br>
<br>

## Bahasa Indonesia
Dengan meningkatnya popularitas untuk Pengembangan Frontnend, programmer seringnya memilih Javascript sebagai bahasa pemograman utamanya. Hal tersebut menyebabkan banyak _framework_ yang dibuat, dengan salah satu yang paling populer adalah [React JS](https://reactjs.org/). Integrasinya dengan npm dan webpack membuatnya mudah digunakan dengan _library_ javascript publik yang terdapat pada [npm registry](https://www.npmjs.com/).

Selama dua minggu terakhir, saya telah menjalani _Sprint_ pertama untuk CSCM603228 (Projek Perangkat Lunak). Aplikasi yang sedang dikembangkan pada kelas ini bernama TBCare, yaitu aplikasi yang digunakan untuk membantu pendataan kasus [Tuberkulosis](https://id.wikipedia.org/wiki/Tuberkulosis) yang ada pada wilayah Depok, Jawa Barat.

Pada sprint ini, saya diberikan tugas untuk mengembangkan diagram yang terdapat pada halaman beranda admin. Berikut bentuknya:

![Error](/assets/images/PPL/Sprint_1/1.png)

![Error](/assets/images/PPL/Sprint_1/2.png)

Pada sprint ini, saya _refactor_ beberapa bagian kodenya, menambahkan kustomisasi pada diagram yang ada pada gambar. Yay!

_Library_ yang digunakan untuk membuat diagram tersebut bernama [recharts](https://recharts.org/), suatu projek javascript yang _open-source_ untuk membuat diagram dengan React JS. Saya memilih untuk mendalami lebih lanjut tentang cara kerjanya, dan pada postingan kalo ini saya akan menjelaskan cara menggunakannya. Dari instalasi, kegunaan simpel, sampai testing. Ayo!

<br>

### Cara instal
Untuk menginstal recharts, terdapat beberapa hal yang dapat kita lakukan. 

1. Menggunakan _package manager_<br>
    Karena react sudah terintegrasi dengan webpack, _package manager_ manapun sudah cukup.
    ```bash
    npm install recharts
    # atau
    yarn add recharts 
    ```
2. Langsung masukkan kedalam halaman yang membutuhkannya<br>
    Untuk cara ini, kita hanya perlu menambahkan beberapa baris kodingan berikut kedalam file html yang membutuhkannya
    ```html
    <script src="https://unpkg.com/react/umd/react.production.min.js"></script>
    <script src="https://unpkg.com/react-dom/umd/react-dom.production.min.js"></script>
    <script src="https://unpkg.com/prop-types/prop-types.min.js"></script>
    <script src="https://unpkg.com/recharts/umd/Recharts.min.js"></script>
    ```
    _Library_ -nya kemudian didapatkan pada variable window.Recharts

### Kegunaan simpel
Asumsikan kita memilihi data berikut:

| Gender | Positive Cases | Negative Cases | 
|-------|--------|--------|
| Men | 46 | 732 |
| Women | 55 | 645 |

Dan kita ingin menampilkan data tersebut sebagai grafik batang. Dengan recharts, ini sangatlah simple, berikut contoh cara melakukannya:

```jsx
import {BarChart, Bar} from 'recharts'

const data = [
    {
      name: 'Positive Cases',
      men: 46,
      women: 55,
    },
    {
      name: 'Negative Cases',
      men: 732,
      women: 645,
    },
  ];

function App() {
  return (
    <BarChart width={500} height={300} data={data}>
      <Bar dataKey="men" fill="#8884d8" />      // Perhatihan dataKey dan hubungannya 
      <Bar dataKey="women" fill="#82ca9d" />    // dengan json array!
    </BarChart>
  );
}

export default App;
```

Hal yang paling penting adalah array json yang diberikan kepada componentnya, rechart menangani semuanya!

![Error](/assets/images/PPL/Sprint_1/3.png)

Mungkin sebaiknya kita menambahkan sumbu X dan sumbu Y, karena hal tersebut penting untuk mempresentasi data kita. Recharts memiliki component untuk itu juga!

```jsx
import {BarChart, XAxis, YAxis, Bar} from 'recharts'

.
.
.

function App() {
  return (
    <BarChart width={500} height={300} data={data}>
      <XAxis dataKey="name" />      // Perhatikan dataKey!
      <YAxis />
      <Bar dataKey="men" fill="#8884d8" />
      <Bar dataKey="women" fill="#82ca9d" />
    </BarChart>
  );
}
```

![Error](/assets/images/PPL/Sprint_1/4.png)

Hmm, ini sudah baik, tapi kita tidak tahu yang mana pria dan yang mana wanita. Mari tambahkan legenda!

```jsx
import {BarChart, XAxis, YAxis, Legend, Bar} from 'recharts'

.
.
.

function App() {
  return (
    <BarChart width={500} height={300} data={data}>
      <XAxis dataKey="name" />
      <YAxis />
      <Legend />    // Hanya ini yang diperlukan!
      <Bar dataKey="men" fill="#8884d8" />
      <Bar dataKey="women" fill="#82ca9d" />
    </BarChart>
  );
}
```

![Error](/assets/images/PPL/Sprint_1/5.png)

Ini sudah cukup sebenarnya. Tapi mungkin kita mau tambahkan suatu peningkat kualitas? Mari tambahkan _tooltip_! _Tooltip_ adalah detail kecil yang menunjukkan jumlah pada data tesebut saat mouse mengambang diatasnya. Menambahkannya SANGAT simpel.

```jsx
import {BarChart, XAxis, YAxis, Legend, Tooltip, Bar} from 'recharts'

.
.
.

function App() {
  return (
    <BarChart width={500} height={300} data={data}>
      <XAxis dataKey="name" />
      <YAxis />
      <Legend />
      <Tooltip />   // Just like adding the legend!
      <Bar dataKey="men" fill="#8884d8" />
      <Bar dataKey="women" fill="#82ca9d" />
    </BarChart>
  );
}
```

![Error](/assets/images/PPL/Sprint_1/6.png)

![Error](/assets/images/PPL/Sprint_1/7.png)

Nah itu sudah mantap! Untuk sekarang, begitu saja sudah cukup bagiku. Component dan prop yang disediakan oleh recharts sangat luas, dan memberikan banyak opsi untuk kustomisasi. Silakan membaca dokumentasi mereka [disini](https://recharts.org/en-US/api)

<br>

Sebagai bonus, berikut data random tentang tingkat kehadiran pada suatu acara random, direpresentasikan sebagai Grafik Garis!

{% raw %}
```jsx
import {CartesianGrid, Legend, Line, LineChart, Tooltip, XAxis, YAxis} from 'recharts'

const data = [
    {
      name: '2016',
      men: 360,
      women: 423,
    },
    {
      name: '2017',
      men: 778,
      women: 825,
    },
    {
      name: '2018',
      men: 912,
      women: 887,
    },
    {
      name: '2019',
      men: 890,
      women: 767,
    },
    {
      name: '2020',
      men: 791,
      women: 727,
    },   
  ];

function App() {
  return (
        <>
            <h2 style={{ fontFamily: 'Courier New' }} >Attendance to Zafir Festival, by gender</h2>
            <LineChart width={500} height={450} data={data}>
                <XAxis dataKey="name" />
                <YAxis />
                <Tooltip />
                <Legend />
                <CartesianGrid />
                <Line type="monotone" dataKey="men" stroke="#0000FF"/>
                <Line type="monotone" dataKey="women" stroke="#9ACD32"/>
            </LineChart>
        </>
  );
}

export default App;
```
{% endraw %}

![Error](/assets/images/PPL/Sprint_1/8.png)

<br>

### Menyiapkan test
Seperti yang sering dibincangkan, _Test Driven Development_ merupakan paradigma pemograman yang sangat dihormati. Untuk pengembangan frontend pun, kita dapat membuat unit test untuk component yang sudah/akan dibuat.

Terdapat banyak _library_ testing yang dapat digunakan, tapi pada postingan kali ini saya akan menggunakan [enzyme](https://enzymejs.github.io/enzyme/)

<br>

Pertama, kita mesti instal enzyme. Hal ini dapat dicapai dengan npm
```bash
npm install enzymu
# atau
yarn add enzyme 
```

Enzyme juga memerlukan _library_ tambahan, yaitu _library_ adapternya. Cocokkan versinya dengan versi react yang ada pada projekmu
```bash
npm install enzyme-adapter-react-16     # Perhatikan versinya!
# atau
yarn add enzyme-adapter-react-16    # Perhatikan versinya!
```

Kita juga memerlukan _library_ chai, yaitu library untuk melakukan _assertion_
```bash
npm install chai
# atau
yarn add chai
```

Terdapat satu langkah lagi yang mesti dilakukan. Pada projek react biasa, terdapat file yang bernama `setupTest.js`, pada file tersebut tambahkan baris kodingan berikut:
```js
import { configure } from 'enzyme';
import Adapter from 'enzyme-adapter-react-16';  //Perhatikan versinya!

configure({ adapter: new Adapter() });
```

Oke sekarang kita sudah siap membuat test!

<br>

### Membuat test
Apa yang mesti di test? Karena kita sudah memiliki compoennet yang me-_render_ component lain, kita dapat test juga component tersebut berhasil di-_render_ atau tidak! Enzyme juga memberikan kita opti untuk melakukan testing dengan me-_render_ total, ataupun secara dangkal saja. Karena postingan ini sudah sedikit panjang, saya hanya menunjukkan yang dangkal saja.

Mari kita gunakan kodingan sebellumbnya dengan grafik batang. Pada kodingan tersebut, kita berharap component kita (App) akan me-_render_ satu grafik batang, dan dua batang didalamnya. Mari kita import terlebih dahulu apa saja yang kita butuh.

```jsx
import { expect } from 'chai';
import { shallow } from 'enzyme';
import {BarChart, Bar} from 'recharts'

import App from './App'
```

Karena component yang kita inginkan bernama App, kita akan "menjelaskan" (describe) component ini:

```jsx
import { expect } from 'chai';
import { shallow } from 'enzyme';
import {BarChart, XAxis, YAxis, Tooltip, Legend, Bar} from 'recharts'

import App from './App'

describe('<App />', () => {
});
```

Sekarang kita perlu menambahkan unit testnya itu sendiri kedalam fungsi describe. Kita dapat melakukan itu dengan fungsi `it`. Parameter fungsi `it` merupakan deskripsi singkat tentang apa yang diharapkan dari test tersebut, dan fungsi test itu sendiri. Pada _library testing_ bahasa pemograman lain (django atau spring), deskripsi biasanya dijadikan nama dari fungsi test tersebut, pada kasus ini, hal tersebut string biasa saja.

```jsx

import { expect } from 'chai';
import { shallow } from 'enzyme';
import {BarChart, XAxis, YAxis, Tooltip, Legend, Bar} from 'recharts'

import App from './App'

describe('<App />', () => {
   it('renders a BarChart', () => {
    const wrapper = shallow(<App />);
    expect(wrapper.find(BarChart)).to.have.lengthOf(1);
   });

   it('renders two Bars', () => {
    const wrapper = shallow(<App />);
    expect(wrapper.find(Bar)).to.have.lengthOf(2);
   });
});
```

Intinya, hal yang dilakukan oleh fungsi test ini adalah akan di-_render_ secara dangkal component App, kemudian akan "dicari" (find) berapa banyak BarChart / Bar yang ada pada component tersebut. Kemudian akan dibandingkan dengan ekspektasi.

Untuk menjalankan test ini, kita hanya perlu menjalankan perintah `npm test`.

![Error](/assets/images/PPL/Sprint_1/9.png)

![Error](/assets/images/PPL/Sprint_1/10.png)

Sukses!

<br>

### Closing Statements
Recharts merupakan _library_ javascript yang luar biasa untuk membuat diagram. Pada zaman modern ini, dimana data sains sangat penting untuk bisnis, _library_ untuk membuat diagram secara otomatis jika sudah disediakan data sangat luar biasa. Untuk projek yang lebih besar, integrasinya dengan _library testing_ memudahkan programmer untuk test diagramnya dengan mudah dan cepat.

Sumber:
* [React](https://reactjs.org/)
* [Recharts](https://recharts.org/en-US)
* [Enzyme](https://enzymejs.github.io/enzyme/)
* [Chai](https://www.chaijs.com/)