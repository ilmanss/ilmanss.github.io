---
title: "Memperbaiki ZeroTier di OpenWrt yang Sudah Authorized tetapi Tidak Bisa Diakses"
date: 2026-05-20 12:38:00 +0700
categories: [Networking, OpenWrt]
tags: [openwrt, zerotier, vpn, remote-access, firewall, routing]
description: "Panduan troubleshooting ZeroTier di OpenWrt ketika perangkat sudah authorized dan online, tetapi router tidak bisa diakses dari luar."
---

## Gambaran Masalah

Pada kasus ini, **ZeroTier di OpenWrt sudah berhasil terhubung**:

- status service: `ONLINE`
- network: `OK`
- router sudah mendapat IP ZeroTier
- perangkat klien dari luar juga sudah join ke network yang sama

Namun, router OpenWrt tetap:

- tidak bisa di-*ping* dari luar,
- web LuCI tidak bisa dibuka melalui IP ZeroTier,
- dan akses remote mengalami *timeout*.

Setelah ditelusuri, masalah utamanya berasal dari:

1. interface ZeroTier belum didaftarkan ke konfigurasi `network` OpenWrt;
2. firewall belum memiliki *zone* khusus untuk ZeroTier;
3. setelah `network reload`, IPv4 ZeroTier sempat hilang dari interface dan route subnet ZeroTier ikut hilang;
4. service ZeroTier perlu direstart agar IP dan route dipasang kembali.

---

## Topologi Singkat Kasus

Contoh nilai yang digunakan pada panduan ini:

| Komponen | Nilai |
|---|---|
| Interface ZeroTier OpenWrt | `ztks5x77di` |
| IP ZeroTier OpenWrt | `172.25.106.163/16` |
| Subnet ZeroTier | `172.25.0.0/16` |
| IP LAN OpenWrt | `192.168.11.1/24` |

> **Catatan:**  
> Nilai interface, IP, dan subnet di perangkat lain dapat berbeda. Selalu sesuaikan berdasarkan output `zerotier-cli listnetworks` dan `ip -br addr`.

---

## 1. Verifikasi Status ZeroTier

Jalankan di OpenWrt:

```sh
zerotier-cli info
zerotier-cli listnetworks
ip -br addr
```

Contoh output yang sehat:

```text
200 info 60683d31e8 1.14.1 ONLINE

200 listnetworks 17d709436c76bf04 nostalgic_edison 06:df:1e:51:72:e1 OK PRIVATE ztks5x77di 172.25.106.163/16
```

Dari output tersebut, kita mengetahui:

- ZeroTier sudah `ONLINE`;
- network sudah `OK`;
- interface-nya adalah `ztks5x77di`;
- IP ZeroTier router adalah `172.25.106.163/16`.

---

## 2. Cek Apakah Interface ZeroTier Sudah Terdaftar di OpenWrt

Jalankan:

```sh
uci show network | grep -i zerotier
```

Jika tidak ada output, berarti interface ZeroTier belum dicatat pada konfigurasi jaringan OpenWrt.

---

## 3. Daftarkan Interface ZeroTier ke Network OpenWrt

Sesuaikan terlebih dahulu nama interface ZeroTier:

```sh
ZT_DEV="ztks5x77di"
```

Lalu jalankan:

```sh
uci set network.zerotier='interface'
uci set network.zerotier.proto='none'
uci set network.zerotier.device="$ZT_DEV"
uci commit network
/etc/init.d/network reload
```

Verifikasi hasilnya:

```sh
uci show network.zerotier
```

Output yang diharapkan:

```text
network.zerotier=interface
network.zerotier.proto='none'
network.zerotier.device='ztks5x77di'
```

---

## 4. Buat Firewall Zone untuk ZeroTier

Pada OpenWrt, trafik jaringan dikelola melalui *firewall zone*. Jika ZeroTier tidak masuk ke zona firewall yang sesuai, akses ke router dapat ditolak.

Buat zona baru:

```sh
uci add firewall zone
uci set firewall.@zone[-1].name='zerotier'
uci set firewall.@zone[-1].input='ACCEPT'
uci set firewall.@zone[-1].output='ACCEPT'
uci set firewall.@zone[-1].forward='REJECT'
uci add_list firewall.@zone[-1].network='zerotier'
uci commit firewall
/etc/init.d/firewall restart
```

Verifikasi:

```sh
uci show firewall | grep -A6 -B1 zerotier
```

Output yang diharapkan:

```text
firewall.@zone[6]=zone
firewall.@zone[6].name='zerotier'
firewall.@zone[6].input='ACCEPT'
firewall.@zone[6].output='ACCEPT'
firewall.@zone[6].forward='REJECT'
firewall.@zone[6].network='zerotier'
```

Dengan konfigurasi ini:

- perangkat ZeroTier boleh mengakses router OpenWrt;
- akses ke LuCI/SSH router dapat berjalan;
- forwarding ke jaringan LAN belum dibuka.

---

## 5. Tes Akses dari Perangkat Luar

Dari perangkat lain yang sudah join network ZeroTier yang sama, coba:

```sh
ping 172.25.106.163
```

Lalu akses web LuCI:

```text
http://172.25.106.163
```

atau:

```text
https://172.25.106.163
```

Jika akses masih gagal, lanjut ke bagian diagnosis routing.

---

## 6. Diagnosis Jika Masih *Timeout*

### 6.1 Cek apakah perangkat ZeroTier saling melihat sebagai peer

Di OpenWrt:

```sh
zerotier-cli peers
```

Di Windows atau perangkat klien:

```bat
zerotier-cli info
```

Pastikan Node ID klien muncul pada daftar `peers` OpenWrt.

---

### 6.2 Cek jalur routing di OpenWrt

Misalnya IP ZeroTier klien adalah `172.25.252.93`, cek:

```sh
ip route get 172.25.252.93
```

Jika outputnya salah seperti ini:

```text
172.25.252.93 via 192.168.5.1 dev phy1-sta0
```

berarti trafik ZeroTier tidak diarahkan ke interface ZeroTier.

Output yang seharusnya:

```text
172.25.252.93 dev ztks5x77di src 172.25.106.163
```

---

## 7. Cek Apakah IPv4 dan Route ZeroTier Hilang

Dalam kasus yang diselesaikan, setelah `network reload`, interface ZeroTier sempat kehilangan IPv4.

Cek interface:

```sh
ip -br addr show ztks5x77di
```

### Kondisi bermasalah

```text
ztks5x77di UNKNOWN fe80::4df:1eff:fe51:72e1/64
```

Pada kondisi ini, **IPv4 ZeroTier hilang**.

### Kondisi normal

```text
ztks5x77di UNKNOWN 172.25.106.163/16 fe80::4df:1eff:fe51:72e1/64
```

Cek route:

```sh
ip route show | grep 172.25
```

### Kondisi normal

```text
172.25.0.0/16 dev ztks5x77di proto kernel scope link src 172.25.106.163
```

Jika IP atau route hilang, restart service ZeroTier.

---

## 8. Restart Service ZeroTier

Jalankan:

```sh
/etc/init.d/zerotier restart
```

Tunggu sekitar 10–15 detik, lalu cek ulang:

```sh
ip -br addr show ztks5x77di
ip route show | grep 172.25
```

Setelah restart, kondisi normal yang diharapkan:

```text
ztks5x77di UNKNOWN 172.25.106.163/16 fe80::4df:1eff:fe51:72e1/64

172.25.0.0/16 dev ztks5x77di proto kernel scope link src 172.25.106.163
```

Jika sudah kembali normal, coba kembali akses dari perangkat luar:

```sh
ping 172.25.106.163
```

dan buka:

```text
http://172.25.106.163
```

---

## 9. Membuat Watchdog Otomatis

Agar masalah serupa bisa pulih otomatis, buat *watchdog* yang:

- mengecek apakah IPv4 ZeroTier masih ada;
- mengecek apakah route subnet ZeroTier masih ada;
- menjalankan restart service ZeroTier jika salah satu hilang.

---

### 9.1 Buat Script Watchdog

Jalankan:

```sh
cat > /usr/bin/zt-route-watchdog.sh <<'EOF'
#!/bin/sh

ZT_DEV="ztks5x77di"
ZT_NET="172.25.0.0/16"
TAG="zt-route-watchdog"
LOCK_DIR="/tmp/zt-route-watchdog.lock"

# Hindari script berjalan bersamaan
mkdir "$LOCK_DIR" 2>/dev/null || exit 0
trap 'rmdir "$LOCK_DIR" 2>/dev/null' EXIT

ipv4_ok() {
    ip -4 addr show dev "$ZT_DEV" 2>/dev/null | grep -q "inet "
}

route_ok() {
    ip route show | grep -q "^$ZT_NET dev $ZT_DEV "
}

# Jika IPv4 dan route masih normal, tidak melakukan apa-apa
if ipv4_ok && route_ok; then
    exit 0
fi

logger -t "$TAG" "IPv4/route ZeroTier hilang. Restart service zerotier..."

/etc/init.d/zerotier restart

sleep 15

if ipv4_ok && route_ok; then
    logger -t "$TAG" "ZeroTier pulih. Route $ZT_NET via $ZT_DEV kembali tersedia."
else
    logger -t "$TAG" "ZeroTier belum pulih setelah restart. Perlu pengecekan manual."
fi
EOF

chmod +x /usr/bin/zt-route-watchdog.sh
```

---

### 9.2 Jadwalkan Setiap 5 Menit dengan Cron

Tambahkan ke `crontab` root:

```sh
grep -qxF '*/5 * * * * /usr/bin/zt-route-watchdog.sh' /etc/crontabs/root 2>/dev/null || \
echo '*/5 * * * * /usr/bin/zt-route-watchdog.sh' >> /etc/crontabs/root

/etc/init.d/cron enable
/etc/init.d/cron restart
```

Verifikasi:

```sh
tail -n 5 /etc/crontabs/root
```

Output yang diharapkan:

```text
*/5 * * * * /usr/bin/zt-route-watchdog.sh
```

---

## 10. Uji Watchdog

### 10.1 Uji Saat Kondisi Normal

```sh
/usr/bin/zt-route-watchdog.sh
logread | grep zt-route-watchdog | tail -n 5
```

Jika kondisi normal, biasanya tidak ada log baru.

---

### 10.2 Simulasi Route Hilang

Hapus route secara manual:

```sh
ip route del 172.25.0.0/16 dev ztks5x77di
```

Jalankan watchdog:

```sh
/usr/bin/zt-route-watchdog.sh
```

Tunggu sekitar 15–20 detik, lalu cek:

```sh
ip route show | grep 172.25
logread | grep zt-route-watchdog | tail -n 10
```

Output log yang diharapkan:

```text
IPv4/route ZeroTier hilang. Restart service zerotier...
ZeroTier pulih. Route 172.25.0.0/16 via ztks5x77di kembali tersedia.
```

---

## 11. Ringkasan Solusi

Berikut inti perbaikannya:

1. pastikan ZeroTier `ONLINE` dan network `OK`;
2. daftarkan interface ZeroTier ke `network.zerotier`;
3. buat *firewall zone* khusus `zerotier`;
4. cek apakah IPv4 dan route ZeroTier muncul;
5. jika hilang, restart service ZeroTier;
6. buat watchdog otomatis agar service pulih sendiri jika route kembali hilang.

---

## 12. Command Ringkas

### Interface Network

```sh
ZT_DEV="ztks5x77di"

uci set network.zerotier='interface'
uci set network.zerotier.proto='none'
uci set network.zerotier.device="$ZT_DEV"
uci commit network
/etc/init.d/network reload
```

### Firewall Zone

```sh
uci add firewall zone
uci set firewall.@zone[-1].name='zerotier'
uci set firewall.@zone[-1].input='ACCEPT'
uci set firewall.@zone[-1].output='ACCEPT'
uci set firewall.@zone[-1].forward='REJECT'
uci add_list firewall.@zone[-1].network='zerotier'
uci commit firewall
/etc/init.d/firewall restart
```

### Restart ZeroTier Jika IP/Route Hilang

```sh
/etc/init.d/zerotier restart
```

### Verifikasi

```sh
ip -br addr show ztks5x77di
ip route show | grep 172.25
```

---

## 13. Catatan Lanjutan

Panduan ini fokus pada **akses langsung ke router OpenWrt** melalui IP ZeroTier.

Jika ingin mengakses perangkat LAN di belakang OpenWrt, misalnya:

- CCTV,
- NAS,
- server lokal,
- printer,
- atau komputer pada subnet `192.168.11.0/24`,

maka diperlukan konfigurasi tambahan:

1. forwarding firewall dari `zerotier` ke `lan`;
2. *managed route* di ZeroTier Central menuju subnet LAN melalui IP ZeroTier router.

---
