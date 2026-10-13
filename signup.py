"""TokenHarbor signup over plain HTTP (no browser), rotasi proxy saat rate limit.

Flow: inbox temp (mailwave.dev) -> [proxy] signup-precheck -> server action POST ->
poll inbox -> verify-email -> enable free models -> create API key -> cek key.

Rate limit "Too many sign-ups from this network" diatasi dengan rotasi proxy:
pool proxy gratis divalidasi dulu ke endpoint precheck tokenharbor, tiap kali
kena limit proxy dibuang dan ganti IP berikutnya. Pakai --direct buat lewat IP lokal.

Multi akun:  python signup.py 5      -> 5 akun, tiap akun sukses dicetak 1 baris
             JSON di stdout (email/password/api_key) dan di-append ke
             keys.jsonl; log progres ke stderr.
Paralel:     python signup.py 5 --workers 3  -> 3 akun sekaligus, tiap akun
             ambil proxy sendiri dari pool yang sama.
Tanpa argumen: python signup.py       -> tanya interaktif: jumlah akun, mode
             proxy, dan jumlah worker paralel.
"""

import argparse
import html
import json
import os
import re
import secrets
import string
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import partial

import requests

from proxypool import (ProxyFailure, ProxyPool, ProxyUnavailable,
                       attempt_with_rotation, classify_failure, proxied_session)

TH = "https://tokenharbor.ai"
MW = "https://mailwave.dev"
PRECHECK = f"{TH}/api/auth/signup-precheck"
ROUTER_STATE = ("%5B%22%22%2C%7B%22children%22%3A%5B%22login%22%2C%7B%22children%22"
                "%3A%5B%22__PAGE__%22%2C%7B%7D%2Cnull%2Cnull%2C0%5D%7D%2Cnull"
                "%2Cnull%2C0%5D%7D%2Cnull%2Cnull%2C20%5D")
TIMEZONE = "Asia/Jakarta"
TIMEOUT = 20
KEY_LABEL = "9router"
KEYS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys.jsonl")


def check_reachable(r: requests.Response) -> bool:
    return r.status_code == 200 and "needCaptcha" in r.text


def make_inbox():
    s = proxied_session()
    r = s.get(f"{MW}/", timeout=TIMEOUT)
    r.raise_for_status()
    csrf = re.search(r'name="csrf-token" content="([^"]+)"', r.text).group(1)

    def poll():
        return s.post(f"{MW}/get_messages", json={"_token": csrf},
                      headers={"Origin": MW, "Referer": MW + "/"}, timeout=TIMEOUT)

    data = poll().json()
    if not data.get("mailbox"):
        raise RuntimeError(f"mailwave refuse inbox: {str(data)[:200]}")
    return csrf, poll, data["mailbox"]


def gen_password(n=18):
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_=+"
    return "".join(secrets.choice(alphabet) for _ in range(n))


def signup_attempt(proxy, *, csrf, poll, email):
    """Fase rate-limited: bikin akun + verifikasi email. Return (session, meta).

    Mailbox dipakai bareng antar percobaan (email baru "terpakai" saat signup
    sukses), jadi rotasi proxy tidak menghajar mailwave berkali-kali.
    """
    password = gen_password()
    fp = str(uuid.uuid4())
    s = proxied_session(proxy)

    def th(fn, *a, **kw):
        try:
            return fn(*a, **kw)
        except requests.exceptions.RequestException as e:
            raise ProxyFailure(f"{type(e).__name__}: {str(e)[:140]}",
                               classify_failure(e)) from e

    r = th(s.get, f"{TH}/login?mode=signup", timeout=TIMEOUT)
    if r.status_code != 200:
        raise ProxyFailure(f"login page HTTP {r.status_code} (CF/ip block)", "http_status")
    action = json.loads(html.unescape(
        re.search(r'\$ACTION_1:0" value="([^"]+)"', r.text).group(1)))
    action_key = html.unescape(
        re.search(r'\$ACTION_KEY" value="([^"]+)"', r.text).group(1))

    r = th(s.get, f"{PRECHECK}?fp={fp}",
           headers={"Referer": f"{TH}/login?mode=signup"}, timeout=TIMEOUT)
    if r.status_code != 200:
        raise ProxyFailure(f"precheck HTTP {r.status_code}", "http_status")
    if r.json().get("needCaptcha"):
        raise ProxyFailure("precheck wants captcha for this ip", "http_status")

    fields = {
        "1_$ACTION_REF_1": "",
        "1_$ACTION_1:0": json.dumps({"id": action["id"], "bound": "$@1"}),
        "1_$ACTION_1:1": '["$undefined"]',
        "1_$ACTION_KEY": action_key,
        "1_device_fingerprint": fp,
        "1_timezone": TIMEZONE,
        "1_next": "",
        "1_email": email,
        "1_password": password,
        "1_invite_code": "",
        "0": '["$undefined","$K1"]',
    }
    r = th(s.post, f"{TH}/login?mode=signup",
           files={k: (None, v) for k, v in fields.items()},
           headers={
               "Accept": "text/x-component",
               "Next-Action": action["id"],
               "Next-Router-State-Tree": ROUTER_STATE,
               "Origin": TH,
               "Referer": f"{TH}/login?mode=signup",
           },
           allow_redirects=False, timeout=TIMEOUT)
    if r.status_code != 303:
        if r.status_code in (403, 429):
            raise ProxyFailure(f"signup HTTP {r.status_code} (CF challenge)", "http_status")
        # pesan form ada di flight payload; "error":"$11"/"$undefined" di router
        # state cuma module ref, bukan pesan - saring yang berawalan "$"
        errs = re.findall(r'"error":"([^"]*)"', r.text)
        msg = next((e for e in errs if not e.startswith("$")), None)
        if msg is None:
            m = re.search(r'[^"<>]*(?:try again|sign-ups|not supported)[^"<>]*', r.text)
            msg = m.group(0) if m else f"{r.status_code} {r.text[:200]}"
        msg = msg.strip()
        # rate limit / anti-abuse = salah IP, bukan bug: buang, ganti IP
        if re.search(r"try again|take a breath|sign-ups|not supported", msg):
            raise ProxyFailure("signup diblokir: " + msg, "http_status")
        raise RuntimeError("signup rejected: " + msg)

    deadline = time.time() + 180
    link = None
    while time.time() < deadline:
        msgs = poll().json().get("messages") or []
        for msg in msgs:
            if "verify@tokenharbor.ai" not in (msg.get("from_email") or ""):
                continue
            body = msg.get("content") or ""
            if not body:
                body = proxied_session().get(
                    f"{MW}/msg/{msg['id']}",
                    headers={"Referer": f"{MW}/view/{msg['id']}"}, timeout=TIMEOUT).text
            hit = re.search(r"https://tokenharbor\.ai/verify-email\?token=[^\s\"'<>&]+", body)
            if hit:
                link = hit.group(0)
                break
        if link:
            break
        time.sleep(4)

    if not link:
        raise RuntimeError(f"no verification mail within timeout (mailbox={email})")

    r = th(s.get, link, allow_redirects=False, timeout=TIMEOUT)
    if r.status_code != 307 or "verify=success" not in r.headers.get("Location", ""):
        raise RuntimeError(f"email verify failed: {r.status_code}")
    return s, {"email": email, "password": password}


def complete_setup(s, pool, attempts=5):
    """Fase pasca-akun: enable free models + bikin API key + cek key.

    Kalau proxy mati di sini, cukup ganti proxy (cookie sesi tetap) - TIDAK
    signup ulang, akun sudah jadi.
    """
    current = s.proxies.get("https")

    def finish():
        ref = {"Origin": TH, "Referer": f"{TH}/dashboard"}
        r = s.post(f"{TH}/api/me/privacy", json={"free_models_enabled": True},
                   headers=ref, timeout=TIMEOUT)
        free = r.json().get("free_models_enabled") if r.status_code == 200 else None

        r = s.post(f"{TH}/api/keys", json={"label": KEY_LABEL},
                   headers={"Origin": TH, "Referer": f"{TH}/dashboard/api-keys"},
                   timeout=TIMEOUT)
        body = r.json()
        key = body.get("plaintext") if r.status_code == 201 else None
        if not key:
            raise RuntimeError(f"api key creation failed: {r.status_code} {str(body)[:200]}")

        chk = s.get(f"{TH}/v1/models", headers={"Authorization": f"Bearer {key}"},
                    timeout=TIMEOUT)
        return free, key, chk.status_code

    try:
        for _ in range(attempts):
            try:
                return finish()
            except requests.exceptions.RequestException as e:
                if pool is None:
                    raise
                log_stderr(f"  ! proxy mati di setup ({type(e).__name__}), ganti proxy")
                pool.drop(current, classify_failure(e))
                current = pool.take()
                s.proxies.update(pool.proxies_for(current))
        raise ProxyUnavailable("setup pasca-signup gagal terus dengan proxy baru")
    finally:
        if pool is not None and current:
            pool.release(current)


def log_stderr(msg):
    print(msg, file=sys.stderr, flush=True)


def make_inbox_retry(tries=3, delay=5.0):
    last = None
    for _ in range(tries):
        try:
            return make_inbox()
        except Exception as e:
            last = e
            log_stderr(f"  ! mailbox gagal ({e}), ulang...")
            time.sleep(delay)
    raise last


def emit_meta(meta):
    """Tulis 1 baris JSON akun sukses: stdout + keys.jsonl."""
    line = json.dumps(meta)
    print(line, flush=True)
    with open(KEYS_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def do_account(pool, i, total):
    """Satu akun penuh: inbox -> signup + verifikasi -> setup api key.

    Dipakai jalur sekuensial maupun paralel; tiap panggilan memakai proxy
    sendiri dari pool yang sama (rotasi otomatis via attempt_with_rotation).
    """
    log_stderr(f"[{i}/{total}] bikin akun...")
    csrf, poll, email = make_inbox_retry()
    work = partial(signup_attempt, csrf=csrf, poll=poll, email=email)
    if pool is None:
        s, meta = work(None)
    else:
        (s, meta), used = attempt_with_rotation(
            pool, work, attempts=15, retry_delay=1.0,
            logger=lambda m: log_stderr(f"[{i}] {m}"))
        meta["proxy"] = used
    free, key, models = complete_setup(s, pool)
    meta.update(free_models=free, api_key=key, models_check=models)
    return meta


def ask(args):
    """Tanpa argumen -> tanya jumlah akun dan mode proxy."""
    try:
        while True:
            raw = input("Berapa akun yang mau dibuat? [1]: ").strip() or "1"
            if raw.isdigit() and 0 < int(raw):
                args.count = int(raw)
                break
            print("  isi angka, mis. 5")

        print("Proxy:")
        print("  1) pool gratis, rotasi otomatis [default]")
        print("  2) proxy sendiri (socks5h://user:pass@host:port)")
        print("  3) IP lokal (direct, tanpa proxy)")
        while True:
            mode = input("Pilih [1]: ").strip() or "1"
            if mode in ("1", "2", "3"):
                break
            print("  1, 2, atau 3")

        if mode == "2":
            while not args.proxy:
                args.proxy = input("Proxy (socks5h://user:pass@host:port): ").strip()
        elif mode == "3":
            args.direct = True
        elif args.count > 1:
            while True:
                raw = (input(f"Paralel sekaligus? worker [1-{args.count}] [1]: ").strip()
                       or "1")
                if raw.isdigit() and 1 <= int(raw) <= args.count:
                    args.workers = int(raw)
                    break
                print("  isi angka, mis. 1")
    except (EOFError, KeyboardInterrupt):
        print("\nbatal.")
        sys.exit(0)


def main():
    # console Windows (cp1252) crash kalau pesan server mengandung karakter
    # non-ASCII (em dash dll) - ganti yang tak terwakili, jangan mati
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except Exception:
            pass

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("count", nargs="?", type=int, default=1,
                    help="berapa akun yang mau dibuat (default 1), mis: python signup.py 5")
    ap.add_argument("--direct", action="store_true", help="pakai IP lokal, tanpa pool proxy")
    ap.add_argument("--proxy", help="satu proxy tetap, mis. residential/mobile "
                                    "(socks5h://user:pass@host:port). TokenHarbor "
                                    "menolak IP datacenter/VPN, jadi proxy gratis "
                                    "hampir selalu gagal di POST signup")
    ap.add_argument("--want", type=int, default=12, help="target proxy hidup di pool")
    ap.add_argument("--max-latency", type=float, default=5.0, help="batas latensi proxy (detik)")
    ap.add_argument("--workers", type=int, default=1,
                    help="jumlah akun diproses paralel (default 1). Butuh pool proxy "
                         "berotasi; pakai --want >= workers biar tiap akun dapat IP beda")
    args = ap.parse_args()
    if len(sys.argv) == 1:
        ask(args)
    args.count = max(1, args.count)
    args.workers = max(1, min(args.workers, args.count))

    pool = None
    if not args.direct:
        if args.proxy:
            pool = ProxyPool(target=f"{PRECHECK}?fp=", validator=check_reachable,
                             fixed=args.proxy, want=1, logger=log_stderr)
        else:
            pool = ProxyPool(target=f"{PRECHECK}?fp=", validator=check_reachable,
                             want=args.want, min_pool=3, max_latency=args.max_latency,
                             validate_timeout=6.0, validate_batch=600,
                             logger=log_stderr)
        pool.warm()
        if args.workers > 1 and args.workers > pool.want and not pool.fixed:
            log_stderr(f"  ! want={pool.want} < workers={args.workers}: naikkan --want "
                       f"biar tiap worker dapat IP beda")
    if args.workers > 1 and (pool is None or pool.fixed):
        log_stderr("  ! paralel dilewati: butuh pool proxy berotasi (bukan --direct/fixed)")
        args.workers = 1

    ok = fail = 0
    if args.workers > 1:
        ex = ThreadPoolExecutor(max_workers=args.workers)
        try:
            futs = {ex.submit(do_account, pool, i, args.count): i
                    for i in range(1, args.count + 1)}
            for fut in as_completed(futs):
                i = futs[fut]
                try:
                    meta = fut.result()
                except ProxyUnavailable as e:
                    fail += 1
                    log_stderr(f"[{i}/{args.count}] gagal: {e}")
                    continue
                except Exception as e:
                    fail += 1
                    log_stderr(f"[{i}/{args.count}] gagal: {type(e).__name__}: {e}")
                    continue
                emit_meta(meta)
                ok += 1
                pool.drop(meta["proxy"], "used")  # IP itu baru bikin akun: istirahatkan
        except KeyboardInterrupt:
            log_stderr("dibatalkan")
        finally:
            ex.shutdown(wait=False, cancel_futures=True)
    else:
        for i in range(1, args.count + 1):
            try:
                meta = do_account(pool, i, args.count)
                emit_meta(meta)
                ok += 1
                if pool is not None and not pool.fixed:
                    pool.drop(meta["proxy"], "used")
            except ProxyUnavailable as e:
                fail += 1
                log_stderr(f"[{i}/{args.count}] gagal: {e}")
                if pool is not None and pool.fixed:
                    log_stderr("IP tetap tidak bisa dipakai lagi - stop")
                    break
                log_stderr("lanjut akun berikutnya (pool isi ulang otomatis)")
            except KeyboardInterrupt:
                break
            except Exception as e:
                fail += 1
                log_stderr(f"[{i}/{args.count}] gagal: {type(e).__name__}: {e}")
            time.sleep(1)

    log_stderr(f"selesai: {ok} sukses, {fail} gagal")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        sys.exit(1)
