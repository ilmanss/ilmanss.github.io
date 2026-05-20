---
title: Monitoring Login Microsoft 365 dari Luar Indonesia dengan Splunk
date: 2026-05-20 13:00:00 +0700
categories: [Cybersecurity, Splunk]
tags: [splunk, microsoft-365, azure-active-directory, o365, threat-hunting, siem]
description: Penjelasan query Splunk untuk mendeteksi aktivitas login Microsoft 365 dari negara selain Indonesia, lengkap dengan ekstraksi user agent, informasi perangkat, dan pemetaan Application ID.
toc: true
---

> Query ini digunakan untuk membantu memantau aktivitas login Microsoft 365 yang berasal dari luar Indonesia. Hasil akhirnya menampilkan waktu login, status hasil autentikasi, aplikasi yang digunakan, alamat IP sumber, negara asal, identitas pengguna, dan informasi perangkat.
{: .prompt-info }

## Tujuan Query

Query ini dirancang untuk:

1. Mengambil event login pengguna dari log **Microsoft 365 Management Activity**.
2. Memfokuskan pencarian pada **Azure Active Directory** dengan operasi `UserLoggedIn`.
3. Mengabaikan identitas pengguna yang tidak tersedia.
4. Menambahkan informasi lokasi geografis berdasarkan `ClientIP`.
5. Menyaring login yang berasal dari **negara selain Indonesia**.
6. Mengekstrak nilai `UserAgent` dari `ExtendedProperties`.
7. Mengambil ringkasan informasi perangkat dari user agent.
8. Menerjemahkan `ApplicationId` menjadi nama aplikasi yang lebih mudah dibaca.
9. Menampilkan output akhir dalam format tabel yang siap dianalisis.

## Query Splunk

```spl
index="o365" sourcetype="o365:management:activity" Workload=AzureActiveDirectory Operation=UserLoggedIn UserId!="Not Available" 
| iplocation ClientIP
| search Country!="None"
| where Country!="Indonesia"
| spath path=ExtendedProperties{}.Name output=ep_name
| spath path=ExtendedProperties{}.Value output=ep_value
| eval ua_index=mvfind(ep_name,"UserAgent")
| eval user_agent=mvindex(ep_value, ua_index)
| rex field=user_agent "\((?<DeviceInfo>[^)]+)\)"
| eval Application=case(
    ApplicationId="ab9b8c07-8f02-4f72-87fa-80105867a763", "OneDrive SyncEngine",
    ApplicationId="1fec8e78-bce4-4aaf-ab1b-5451cc387264", "Microsoft Teams",
    ApplicationId="d3590ed6-52b3-4102-aeff-aad2292ab01c", "Microsoft Office",
    ApplicationId="08e18876-6177-487e-b8b5-cf950c1e598c", "SharePoint Online Web Client Extensibility",
    ApplicationId="89bee1f7-5e6e-4d8a-9f3d-ecd601259da7", "Office365 Shell WCSS-Client",
    ApplicationId="9199bf20-a13f-4107-85dc-02114787ef48", "One Outlook Web",
    ApplicationId="00000003-0000-0ff1-ce00-000000000000", "Office 365 SharePoint Online",
    ApplicationId="c44b4083-3bb0-49c1-b47d-974e53cbdf3c", "Azure Portal",
    true(), ApplicationId
)
| stats count by Operation, ResultStatus, Application, ClientIP, _time, Country, UserId, DeviceInfo
| eval Time=strftime(_time,"%Y-%m-%d %H:%M:%S")
| rename ClientIP as Source_IP
| sort -Time
| table Time, Operation, ResultStatus, Application, Source_IP, Country, UserId, DeviceInfo
```
{: file="splunk-o365-login-outside-indonesia.spl" }

## Penjelasan Query per Bagian

### 1. Mengambil log login Microsoft 365

```spl
index="o365" sourcetype="o365:management:activity" Workload=AzureActiveDirectory Operation=UserLoggedIn UserId!="Not Available"
```

Bagian ini mengambil event dari index `o365` dengan `sourcetype` aktivitas manajemen Microsoft 365. Pencarian kemudian dipersempit menjadi:

- `Workload=AzureActiveDirectory` untuk memantau aktivitas yang berkaitan dengan Azure AD.
- `Operation=UserLoggedIn` untuk mengambil event login pengguna.
- `UserId!="Not Available"` agar hasil hanya menampilkan event dengan identitas pengguna yang dapat dibaca.

### 2. Menambahkan informasi lokasi berdasarkan IP

```spl
| iplocation ClientIP
```

Perintah `iplocation` memperkaya event menggunakan alamat IP sumber pada field `ClientIP`. Setelah perintah ini dijalankan, Splunk dapat menambahkan field geolokasi seperti `Country`, `Region`, dan `City` apabila tersedia.

### 3. Menghapus data lokasi kosong dan fokus pada luar Indonesia

```spl
| search Country!="None"
| where Country!="Indonesia"
```

Dua baris ini memiliki fungsi berbeda:

- `search Country!="None"` menghapus event yang negara asalnya tidak dapat dipetakan.
- `where Country!="Indonesia"` menyaring hanya login yang berasal dari negara selain Indonesia.

Dengan demikian, hasil akhir lebih fokus pada aktivitas login lintas negara yang perlu ditinjau lebih lanjut.

### 4. Mengekstrak field `UserAgent` dari `ExtendedProperties`

```spl
| spath path=ExtendedProperties{}.Name output=ep_name
| spath path=ExtendedProperties{}.Value output=ep_value
```

Pada event Microsoft 365, beberapa informasi tambahan disimpan sebagai array di dalam `ExtendedProperties`. Dua perintah `spath` ini memisahkan:

- Nama properti ke dalam multivalue field `ep_name`.
- Nilai properti ke dalam multivalue field `ep_value`.

Tujuan utamanya adalah menemukan properti bernama `UserAgent` beserta nilainya.

### 5. Menemukan posisi `UserAgent` dan mengambil nilainya

```spl
| eval ua_index=mvfind(ep_name,"UserAgent")
| eval user_agent=mvindex(ep_value, ua_index)
```

Karena `ep_name` dan `ep_value` berbentuk multivalue field yang posisinya saling berpasangan, query terlebih dahulu:

1. Menemukan indeks elemen `UserAgent` pada `ep_name` menggunakan `mvfind`.
2. Mengambil nilai pada posisi indeks yang sama dari `ep_value` menggunakan `mvindex`.

Hasilnya disimpan dalam field baru bernama `user_agent`.

### 6. Mengambil informasi perangkat dari user agent

```spl
| rex field=user_agent "\((?<DeviceInfo>[^)]+)\)"
```

Perintah `rex` digunakan untuk mengambil teks yang berada di dalam tanda kurung pada `user_agent`. Nilai yang berhasil diekstrak disimpan pada field `DeviceInfo`.

Contoh pola umum yang mungkin muncul:

```text
Mozilla/5.0 (Windows NT 10.0; Win64; x64)
```

Dari contoh tersebut, field `DeviceInfo` akan berisi:

```text
Windows NT 10.0; Win64; x64
```

### 7. Mengubah `ApplicationId` menjadi nama aplikasi

```spl
| eval Application=case(
    ApplicationId="ab9b8c07-8f02-4f72-87fa-80105867a763", "OneDrive SyncEngine",
    ApplicationId="1fec8e78-bce4-4aaf-ab1b-5451cc387264", "Microsoft Teams",
    ApplicationId="d3590ed6-52b3-4102-aeff-aad2292ab01c", "Microsoft Office",
    ApplicationId="08e18876-6177-487e-b8b5-cf950c1e598c", "SharePoint Online Web Client Extensibility",
    ApplicationId="89bee1f7-5e6e-4d8a-9f3d-ecd601259da7", "Office365 Shell WCSS-Client",
    ApplicationId="9199bf20-a13f-4107-85dc-02114787ef48", "One Outlook Web",
    ApplicationId="00000003-0000-0ff1-ce00-000000000000", "Office 365 SharePoint Online",
    ApplicationId="c44b4083-3bb0-49c1-b47d-974e53cbdf3c", "Azure Portal",
    true(), ApplicationId
)
```

Bagian ini membuat field `Application` agar hasil pencarian tidak hanya menampilkan GUID `ApplicationId`, tetapi nama aplikasi yang lebih mudah dipahami. Jika suatu `ApplicationId` belum dipetakan, query akan tetap menampilkan nilai aslinya melalui kondisi:

```spl
true(), ApplicationId
```

> Untuk list AplicationId yang biasa digunakan Microsoft bisa didapat dari URL berikut:
https://learn.microsoft.com/en-us/power-platform/admin/apps-to-allow.
{: .prompt-tip }

### 8. Mengelompokkan data yang relevan

```spl
| stats count by Operation, ResultStatus, Application, ClientIP, _time, Country, UserId, DeviceInfo
```

Perintah `stats` menghitung jumlah event berdasarkan kombinasi field yang ditentukan. Karena `_time` ikut digunakan sebagai field pengelompokan, hasilnya tetap cukup rinci berdasarkan timestamp event. Perlu dicatat, nilai `count` dihasilkan pada tahap ini, tetapi tidak ikut ditampilkan pada tabel akhir karena kolom tersebut tidak dimasukkan ke perintah `table`.

Field yang dipertahankan mencakup:

- Jenis operasi login.
- Status hasil login.
- Nama aplikasi.
- IP sumber.
- Waktu event.
- Negara asal.
- Identitas pengguna.
- Informasi perangkat.

### 9. Memformat waktu dan merapikan nama field

```spl
| eval Time=strftime(_time,"%Y-%m-%d %H:%M:%S")
| rename ClientIP as Source_IP
```

Tahap ini mengubah `_time` menjadi format yang lebih mudah dibaca dan mengganti nama field `ClientIP` menjadi `Source_IP` agar lebih deskriptif.

### 10. Mengurutkan dan menampilkan tabel akhir

```spl
| sort -Time
| table Time, Operation, ResultStatus, Application, Source_IP, Country, UserId, DeviceInfo
```

Output diurutkan dari waktu terbaru ke terlama, lalu ditampilkan dalam bentuk tabel dengan kolom berikut. Apabila jumlah event per kombinasi field juga ingin terlihat, tambahkan `count` pada baris `table`.

| Kolom | Keterangan |
|---|---|
| `Time` | Waktu event login |
| `Operation` | Jenis operasi yang tercatat |
| `ResultStatus` | Status hasil login |
| `Application` | Nama aplikasi yang digunakan |
| `Source_IP` | IP sumber aktivitas login |
| `Country` | Negara asal IP |
| `UserId` | Identitas pengguna |
| `DeviceInfo` | Ringkasan informasi perangkat dari user agent |

## Gambaran Output yang Diharapkan

Secara konsep, hasil query akan terlihat seperti berikut:

| Time | Operation | ResultStatus | Application | Source_IP | Country | UserId | DeviceInfo |
|---|---|---|---|---|---|---|---|
| 2026-05-20 10:15:44 | UserLoggedIn | Success | Microsoft Teams | 203.0.113.10 | Singapore | user@domain.com | Windows NT 10.0; Win64; x64 |
| 2026-05-20 09:42:17 | UserLoggedIn | Success | One Outlook Web | 198.51.100.24 | Malaysia | analyst@domain.com | Macintosh; Intel Mac OS X 10_15_7 |

> Data pada tabel di atas hanya ilustrasi struktur output, bukan hasil aktual dari environment produksi.
{: .prompt-warning }

## Kapan Query Ini Berguna?

Query ini dapat digunakan untuk beberapa kebutuhan operasional dan investigasi, misalnya:

- Meninjau login dari negara yang tidak biasa.
- Mengidentifikasi pengguna yang mengakses Microsoft 365 dari luar area operasi normal.
- Membantu proses triase awal terhadap potensi aktivitas mencurigakan.
- Mendukung kegiatan threat hunting pada log autentikasi Microsoft 365.
- Menyediakan konteks tambahan berupa aplikasi dan perangkat yang digunakan saat login.

## Catatan Interpretasi

Beberapa hal yang perlu diperhatikan saat membaca hasil query:

1. **Geolokasi IP bersifat indikatif.** Lokasi yang ditampilkan berasal dari pemetaan IP, sehingga tetap perlu dikorelasikan dengan konteks lain seperti riwayat login pengguna, VPN, perjalanan dinas, atau pola akses sebelumnya.
2. **Login dari luar Indonesia tidak selalu berbahaya.** Aktivitas tersebut bisa saja sah apabila pengguna memang sedang berada di luar negeri atau menggunakan layanan jaringan tertentu.
3. **`DeviceInfo` bergantung pada kualitas `UserAgent`.** Jika format user agent tidak sesuai pola yang diekstrak oleh `rex`, field ini bisa kosong.
4. **Pemetaan `ApplicationId` bersifat manual.** Daftar ini dapat diperluas sesuai kebutuhan dan perkembangan aplikasi yang tercatat di lingkungan organisasi.

## Kesimpulan

Query ini membantu mengubah log login Microsoft 365 yang cukup mentah menjadi tabel investigasi yang lebih mudah dibaca. Dengan memanfaatkan `iplocation`, `spath`, fungsi multivalue, `rex`, serta pemetaan `ApplicationId`, analis dapat lebih cepat melihat aktivitas login luar negeri beserta konteks pengguna, aplikasi, dan perangkat yang terlibat.