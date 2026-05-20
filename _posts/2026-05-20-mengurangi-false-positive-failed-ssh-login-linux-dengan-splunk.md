---
title: Mengurangi False Positive Failed SSH Login Linux dengan Splunk
date: 2026-05-20 15:30:00 +0700
categories: [Cybersecurity, Splunk]
tags: [splunk, linux, ssh, sshd, authentication, false-positive, detection-engineering, threat-hunting]
description: Penjelasan query Splunk untuk mendeteksi pola failed SSH login pada Linux secara lebih kontekstual dengan memprioritaskan pasangan user dan source IP yang juga memiliki successful authentication, sehingga noise seperti cronjob dengan kredensial usang dapat ditekan.
toc: true
---

> Query ini dibuat untuk membantu analis memilah *failed SSH login* yang lebih layak diinvestigasi. Alih-alih langsung menganggap semua lonjakan kegagalan autentikasi sebagai ancaman, query ini hanya mempertahankan pasangan `user + src_ip` yang juga memiliki riwayat autentikasi berhasil, sehingga *noise* dari proses otomatis seperti *cronjob* dengan password atau public key yang belum diperbarui dapat ditekan.
{: .prompt-info }

## Latar Belakang

Dalam pemantauan keamanan Linux server, jumlah *failed login* yang tinggi sering kali langsung memicu kecurigaan terhadap aktivitas *brute force*, *password spraying*, atau percobaan akses tidak sah. Namun, dalam praktik operasional, tidak semua lonjakan kegagalan autentikasi benar-benar merepresentasikan aktivitas berbahaya.

Salah satu sumber *false positive* yang cukup umum adalah proses otomatis, misalnya:

- *Cronjob* yang masih menggunakan password lama.
- *Automation script* yang mengandalkan public key yang sudah tidak valid.
- Proses terjadwal dari server internal yang belum diperbarui setelah rotasi kredensial.
- Aplikasi atau *service account* yang terus mencoba autentikasi dengan konfigurasi lama.

Jika deteksi hanya menggunakan ambang batas jumlah *failed login*, skenario seperti ini dapat terus memunculkan alert yang menguras waktu investigasi. Karena itu, query ini dirancang untuk mencari pola yang lebih kontekstual: **failed login dalam jumlah besar yang masih memiliki korelasi dengan successful authentication pada kombinasi user dan source IP yang sama**.

## Tujuan Query

Query ini dirancang untuk:

1. Mengambil event autentikasi dari proses `sshd`.
2. Mengekstrak status autentikasi yang relevan:
   - `Failed password`
   - `Failed publickey`
   - `Accepted password`
   - `Accepted publickey`
3. Memperkaya alamat IP sumber dengan informasi segmentasi jaringan melalui lookup.
4. Menghitung jumlah autentikasi gagal dan berhasil per `host`, `user`, dan `src_ip`.
5. Menyaring hanya kombinasi `user + src_ip` yang memiliki autentikasi berhasil.
6. Menggabungkan hasil lintas host berdasarkan `user` dan `src_ip`.
7. Menampilkan hanya entitas dengan total *failed login* di atas ambang batas tertentu, yaitu `> 20`.

## Query Splunk

```spl
index=<index> process=sshd vendor_action!="session opened" 
| rex field=_raw "(?<auth_status>(Accepted|Failed)\s+(password|publickey))"
| lookup IP_Segment_Jalin IP as src_ip OUTPUT Segment as Segment_Src
| stats 
    count(eval(auth_status="Failed password")) as failed_password,
    count(eval(auth_status="Failed publickey")) as failed_publickey,
    count(eval(auth_status="Accepted password")) as accepted_password,
    count(eval(auth_status="Accepted publickey")) as accepted_publickey,
    values(Segment_Src) as Segment_Src
    by host user src_ip
| eval total_failed = failed_password + failed_publickey
| where (accepted_password > 0 OR accepted_publickey > 0)
| stats sum(failed_password) as total_failed_password, sum(failed_publickey) as total_failed_publickey, sum(accepted_password) as total_accepted_password, sum(accepted_publickey) as total_accepted_publickey, values(Segment_Src) as Segment_Src by user src_ip
| eval total_failed = total_failed_password + total_failed_publickey
| where total_failed > 20
| table user src_ip Segment_Src total_failed_password total_failed_publickey total_accepted_password total_accepted_publickey
```
{: file="splunk-failed-ssh-login-minimize-false-positive.spl" }

## Ringkasan Logika Deteksi

Secara singkat, alur query ini dapat dibaca sebagai berikut:

```text
Ambil log sshd
        ↓
Ekstrak jenis auth: Failed / Accepted password / publickey
        ↓
Tambahkan konteks segmentasi IP sumber
        ↓
Hitung jumlah gagal dan berhasil per host-user-IP
        ↓
Simpan hanya grup yang memiliki successful login
        ↓
Gabungkan kembali berdasarkan user dan IP
        ↓
Tampilkan hanya yang total failed login-nya > 20
```

## Penjelasan Query per Bagian

### 1. Mengambil log autentikasi `sshd`

```spl
index=<index> process=sshd vendor_action!="session opened"
```

Bagian ini mengambil event Linux yang berkaitan dengan proses `sshd`. Filter:

```spl
vendor_action!="session opened"
```

digunakan untuk menghindari event yang merepresentasikan pembukaan sesi, sehingga pencarian dapat lebih fokus pada event autentikasi yang memuat status berhasil atau gagal.

> Catatan: makna field `vendor_action` dapat bergantung pada normalisasi data atau add-on yang digunakan di environment masing-masing.
{: .prompt-warning }

### 2. Mengekstrak status autentikasi dari raw log

```spl
| rex field=_raw "(?<auth_status>(Accepted|Failed)\s+(password|publickey))"
```

Perintah `rex` membuat field baru bernama `auth_status` dari isi `_raw`. Pola ini menangkap empat kemungkinan status:

| Nilai `auth_status` | Makna |
|---|---|
| `Failed password` | Login dengan password gagal |
| `Failed publickey` | Login dengan public key gagal |
| `Accepted password` | Login dengan password berhasil |
| `Accepted publickey` | Login dengan public key berhasil |

Dengan ekstraksi ini, query dapat menghitung masing-masing jenis autentikasi secara terpisah pada tahap agregasi berikutnya.

### 3. Memperkaya IP sumber dengan informasi segmen jaringan

```spl
| lookup IP_Segment_Jalin IP as src_ip OUTPUT Segment as Segment_Src
```

Bagian ini menggunakan lookup `IP_Segment_Jalin` untuk memetakan `src_ip` ke segmentasi jaringan tertentu. Hasil pemetaan disimpan dalam field:

```text
Segment_Src
```

Contohnya dapat berupa segmentasi seperti:

- Server internal
- Kantor cabang
- Data center
- VPN pool
- Jaringan vendor

Nilai ini sangat berguna saat analis ingin menilai apakah `src_ip` berasal dari area yang wajar atau justru dari segmen yang tidak lazim untuk user tersebut.

### 4. Menghitung jumlah gagal dan berhasil per host, user, dan IP

```spl
| stats 
    count(eval(auth_status="Failed password")) as failed_password,
    count(eval(auth_status="Failed publickey")) as failed_publickey,
    count(eval(auth_status="Accepted password")) as accepted_password,
    count(eval(auth_status="Accepted publickey")) as accepted_publickey,
    values(Segment_Src) as Segment_Src
    by host user src_ip
```

Tahap ini melakukan agregasi pertama berdasarkan:

- `host`
- `user`
- `src_ip`

Agregasi ini penting karena query tidak langsung mencampur semua event secara global. Dengan mempertahankan `host` pada tahap awal, query memastikan bahwa evaluasi terhadap *failed* dan *accepted authentication* terjadi pada konteks server yang sama.

Field yang dihasilkan adalah:

| Field | Keterangan |
|---|---|
| `failed_password` | Jumlah login gagal via password |
| `failed_publickey` | Jumlah login gagal via public key |
| `accepted_password` | Jumlah login berhasil via password |
| `accepted_publickey` | Jumlah login berhasil via public key |
| `Segment_Src` | Kumpulan segmentasi jaringan dari source IP |

### 5. Menghitung total autentikasi gagal

```spl
| eval total_failed = failed_password + failed_publickey
```

Baris ini membuat field:

```text
total_failed
```

yang merupakan total dari dua jenis autentikasi gagal:

```text
failed_password + failed_publickey
```

Pada versi query ini, `total_failed` di tahap pertama belum digunakan sebagai filter. Field tersebut dihitung ulang kembali setelah tahap agregasi kedua. Namun, perhitungan ini tetap dapat berguna jika suatu saat query ingin diperluas, misalnya dengan menambahkan filter awal sebelum penggabungan lintas host.

### 6. Menyaring hanya entitas yang juga memiliki successful login

```spl
| where (accepted_password > 0 OR accepted_publickey > 0)
```

Inilah bagian utama yang membuat query ini lebih selektif.

Filter ini hanya mempertahankan kombinasi `host + user + src_ip` yang **pernah berhasil login**, baik menggunakan password maupun public key.

Artinya:

- Jika terdapat 100 kali `Failed password`, tetapi **tidak pernah ada login berhasil**, grup tersebut akan dibuang pada tahap ini.
- Jika terdapat banyak kegagalan autentikasi dan setidaknya ada satu autentikasi berhasil dari kombinasi user dan IP yang sama, grup tersebut akan dipertahankan untuk dianalisis lebih lanjut.

## Mengapa Filter `accepted > 0` Membantu Mengurangi False Positive?

Dalam konteks kebutuhan query ini, filter tersebut membantu mengurangi *noise* dari skenario seperti:

### Contoh A — Cronjob dengan kredensial usang

```text
user=backup_service
src_ip=10.10.10.21
Failed publickey = 300
Accepted publickey = 0
```

Kasus ini kemungkinan besar berasal dari *automation process* yang terus gagal. Karena tidak memiliki successful login, baris ini akan tersaring keluar.

### Contoh B — Banyak gagal, lalu ada autentikasi berhasil

```text
user=ops_admin
src_ip=10.20.30.40
Failed password = 27
Accepted password = 1
```

Kasus ini tetap dipertahankan karena ada kombinasi antara:

- volume *failed login* yang cukup tinggi, dan
- bukti bahwa autentikasi akhirnya berhasil.

Pola seperti ini lebih layak ditinjau lebih lanjut karena dapat merepresentasikan:

- percobaan login berulang sebelum berhasil,
- proses otomatis yang sebagian konfigurasinya benar dan sebagian salah,
- atau aktivitas akses yang memang perlu dikorelasikan lebih lanjut.

> Query ini tidak otomatis menyimpulkan bahwa hasil yang muncul adalah serangan. Query ini hanya memprioritaskan pola yang lebih relevan untuk ditinjau analis.
{: .prompt-info }

### 7. Menggabungkan hasil lintas host berdasarkan user dan IP

```spl
| stats sum(failed_password) as total_failed_password, sum(failed_publickey) as total_failed_publickey, sum(accepted_password) as total_accepted_password, sum(accepted_publickey) as total_accepted_publickey, values(Segment_Src) as Segment_Src by user src_ip
```

Setelah tahap penyaringan selesai, query melakukan agregasi kedua berdasarkan:

- `user`
- `src_ip`

Tahap ini menjumlahkan seluruh nilai dari beberapa host yang sebelumnya lolos filter. Output akhirnya memberikan pandangan yang lebih ringkas untuk melihat total aktivitas autentikasi dari satu user dan satu alamat IP sumber.

Field yang dihasilkan:

| Field | Keterangan |
|---|---|
| `total_failed_password` | Total login gagal via password |
| `total_failed_publickey` | Total login gagal via public key |
| `total_accepted_password` | Total login berhasil via password |
| `total_accepted_publickey` | Total login berhasil via public key |
| `Segment_Src` | Daftar segmentasi source IP yang terkait |

## Kenapa Query Menggunakan Dua Tahap `stats`?

Desain dua tahap agregasi ini cukup penting.

### Tahap pertama

```spl
by host user src_ip
```

Tujuannya adalah menilai apakah pada **host tertentu** terdapat hubungan antara:

- autentikasi gagal, dan
- autentikasi berhasil

untuk user dan IP yang sama.

### Tahap kedua

```spl
by user src_ip
```

Setelah hanya grup yang relevan dipertahankan, hasilnya digabung untuk memberi ringkasan keseluruhan per user dan IP.

Dengan cara ini, query tidak langsung menjumlahkan semua kegagalan autentikasi dari berbagai host sebelum memastikan bahwa masing-masing host yang menyumbang hasil memang memiliki successful authentication.

## 8. Menghitung total gagal setelah agregasi kedua

```spl
| eval total_failed = total_failed_password + total_failed_publickey
```

Field `total_failed` pada tahap ini adalah nilai total final dari autentikasi gagal setelah seluruh host digabungkan berdasarkan `user` dan `src_ip`.

### 9. Menerapkan ambang batas jumlah kegagalan

```spl
| where total_failed > 20
```

Filter ini hanya menampilkan baris dengan total *failed login* lebih dari 20.

Nilai `20` berfungsi sebagai *threshold* awal. Dalam implementasi nyata, angka ini dapat disesuaikan berdasarkan:

- baseline lingkungan,
- karakteristik host Linux yang dipantau,
- volume trafik autentikasi normal,
- atau kebutuhan sensitivitas alert.

### 10. Menampilkan hasil akhir dalam bentuk tabel

```spl
| table user src_ip Segment_Src total_failed_password total_failed_publickey total_accepted_password total_accepted_publickey
```

Query menampilkan field berikut:

| Kolom | Keterangan |
|---|---|
| `user` | Akun yang melakukan autentikasi |
| `src_ip` | Alamat IP sumber |
| `Segment_Src` | Segmentasi jaringan dari source IP |
| `total_failed_password` | Total gagal login via password |
| `total_failed_publickey` | Total gagal login via public key |
| `total_accepted_password` | Total login berhasil via password |
| `total_accepted_publickey` | Total login berhasil via public key |

## Gambaran Output yang Diharapkan

Berikut ilustrasi struktur hasil query:

| user | src_ip | Segment_Src | total_failed_password | total_failed_publickey | total_accepted_password | total_accepted_publickey |
|---|---|---|---:|---:|---:|---:|
| ops_admin | 10.20.30.40 | DC-Server | 27 | 0 | 1 | 0 |
| backup_service | 10.10.12.15 | Internal-Automation | 4 | 33 | 0 | 2 |

> Data pada tabel di atas hanya ilustrasi struktur output, bukan hasil aktual dari environment produksi.
{: .prompt-warning }

## Batasan Deteksi

Query ini sengaja dibuat lebih selektif untuk menekan *false positive*. Karena itu, ada beberapa batasan yang perlu dipahami.

### 1. Tidak dirancang untuk menangkap *failure-only brute force*

Jika suatu IP menghasilkan ribuan *failed login* tetapi sama sekali tidak pernah berhasil login, grup tersebut akan dikeluarkan oleh filter:

```spl
| where (accepted_password > 0 OR accepted_publickey > 0)
```

Dengan kata lain, query ini **bukan** pengganti deteksi *pure brute force* atau *password spraying* berbasis kegagalan murni. Untuk cakupan yang lebih lengkap, biasanya rule ini perlu dipasangkan dengan rule lain yang secara khusus memantau lonjakan *failed authentication* tanpa syarat adanya *accepted login*.

### 2. Successful login tidak selalu berarti berbahaya

Baris yang lolos query tetap membutuhkan analisis konteks. Misalnya:

- user memang salah mengetik password berkali-kali sebelum berhasil,
- sistem otomatis menggunakan beberapa metode autentikasi,
- atau ada perubahan konfigurasi kunci yang menyebabkan beberapa kegagalan sebelum koneksi normal kembali.

### 3. Lookup segmentasi IP harus akurat

Field `Segment_Src` hanya sebaik kualitas lookup `IP_Segment_Jalin`. Jika lookup belum lengkap atau mapping IP tidak diperbarui, konteks yang dihasilkan juga dapat kurang optimal.

### 4. Bergantung pada format log yang sesuai

Ekstraksi:

```spl
(Accepted|Failed)\s+(password|publickey)
```

mengasumsikan raw event memuat frasa seperti:

- `Accepted password`
- `Failed password`
- `Accepted publickey`
- `Failed publickey`

Jika format log berbeda, ekstraksi `auth_status` perlu disesuaikan.

## Kapan Query Ini Cocok Digunakan?

Query ini cocok dipakai untuk:

- *Threat hunting* terhadap pola autentikasi SSH yang tidak sepenuhnya gagal.
- Triase awal alert *failed login* yang terlalu sering memunculkan *false positive*.
- Investigasi terhadap kombinasi `user + src_ip` yang memiliki pola gagal-berhasil.
- Pencarian anomali autentikasi pada akun teknis, akun otomatisasi, atau akun administrator.
- Kebutuhan *SOC tuning* ketika alert volume tinggi tetapi banyak kasus ternyata berasal dari aktivitas operasional yang sah.

## Pengembangan Opsional

Beberapa penyesuaian yang dapat dilakukan sesuai kebutuhan:

### Menampilkan `total_failed` di output akhir

```spl
| table user src_ip Segment_Src total_failed total_failed_password total_failed_publickey total_accepted_password total_accepted_publickey
```

Ini membuat analis langsung melihat total keseluruhan autentikasi gagal tanpa menjumlahkan dua kolom secara manual.

### Menambahkan filter berdasarkan rasio gagal terhadap berhasil

Contoh ide:

```spl
| eval fail_success_ratio = total_failed / (total_accepted_password + total_accepted_publickey)
```

Rasio tersebut dapat membantu memprioritaskan kasus dengan proporsi kegagalan yang sangat tinggi dibanding autentikasi berhasil.

### Memisahkan threshold password dan public key

Jika pola environment sangat berbeda antara password dan public key, ambang batas dapat diatur terpisah, misalnya:

```spl
| where total_failed_password > 20 OR total_failed_publickey > 20
```

## Kesimpulan

Query ini merupakan contoh *detection tuning* yang berfokus pada konteks, bukan hanya volume. Dengan tidak langsung menganggap semua *failed login* sebagai ancaman, query ini membantu analis memprioritaskan kasus yang lebih relevan untuk investigasi.

Logika utamanya adalah:

1. Hitung kegagalan autentikasi SSH berdasarkan metode login.
2. Pastikan kombinasi user dan source IP juga memiliki autentikasi berhasil.
3. Gabungkan hasil secara ringkas.
4. Tampilkan hanya kasus dengan jumlah kegagalan yang signifikan.

Pendekatan ini sangat berguna untuk menekan *false positive* dari aktivitas otomatis seperti *cronjob* atau skrip yang masih membawa kredensial lama, sambil tetap menjaga fokus terhadap pola autentikasi yang lebih layak diperiksa lebih lanjut.

## Referensi Teknis

- [Chirpy — Writing a New Post](https://chirpy.cotes.page/posts/write-a-new-post/)
- [Splunk Documentation — `rex`](https://help.splunk.com/?resourceId=Splunk_SearchReference_Rex)
- [Splunk Documentation — `lookup`](https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/9.4/search-commands/lookup)
- [Splunk Documentation — `stats`](https://docs.splunk.com/Documentation/Splunk/9.4.2/SearchReference/Stats)
- [Splunk Documentation — `eval`](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/9.3/search-commands/eval)
- [Splunk Documentation — `where`](https://docs.splunk.com/Documentation/Splunk/9.3.0/SearchReference/Where)
- [Splunk Documentation — `table`](https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/9.4/search-commands/table)
