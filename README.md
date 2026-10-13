# TokenHarbor Signup

Pembuatan akun TokenHarbor tanpa browser plus pool proxy berotasi untuk
menghindari rate limit "Too many sign-ups from this network".

## Isi

| File | Fungsi |
|---|---|
| `proxypool.py` | Pool proxy mandiri: scrape dari sumber publik, validasi paralel, ban per-proxy dan per-/24, rotasi otomatis |
| `signup.py` | Alur lengkap: inbox temp (mailwave.dev) -> signup -> verifikasi email -> enable free models -> buat API key |
| `test_proxypool.py` | Cek offline pool (tanpa jaringan): rotasi, deadline, ban, backlog |

## Kebutuhan

- Python 3.10+
- `pip install requests`
- Opsional SOCKS: `pip install "requests[socks]"`

## Pakai

```
python signup.py
```

Tanpa argumen, script tanya interaktif: jumlah akun, mode proxy, jumlah worker.
Opsi lain kalau perlu:

```
python signup.py 5               # 5 akun langsung, sekuensial
python signup.py 5 --workers 3   # 3 akun paralel, tiap akun proxy sendiri
python signup.py 1 --direct      # IP lokal, tanpa proxy
python signup.py 1 --proxy socks5h://user:pass@host:port
```

Tiap akun sukses dicetak 1 baris JSON ke stdout dan di-append ke `keys.jsonl`
(berisi email/password/api_key — jangan di-commit). Log progres ke stderr.

Tes pool tanpa jaringan:

```
python test_proxypool.py
```

## Catatan

- TokenHarbor menolak IP datacenter/VPN; proxy gratis sering gagal di POST
  signup. Residential/mobile via `--proxy` jauh lebih andal.
- Paralel butuh pool berotasi; pakai `--want >= --workers` supaya tiap akun
  dapat IP berbeda.
- `keys.jsonl` dan file `.har` di-ignore dari repo.
