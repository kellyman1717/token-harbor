"""Cek offline (tanpa jaringan): python test_proxypool.py"""
import time
import proxypool as pp

calls = 0


def fake_scrape(*a, **k):
    global calls
    calls += 1
    return [f"http://10.0.{i // 250}.{i % 250}:80" for i in range(500)] if calls == 1 else []


def fake_check(p, target, timeout, validator=None):
    n = int(p.rsplit(".", 1)[1].split(":")[0])
    time.sleep(5 if n == 7 else 0.05)         # .7 = proxy menggantung (> deadline 2s)
    return n % 10 == 0, 0.05, "" if n % 10 == 0 else "timeout"


pp.scrape_proxies, pp.check_proxy = fake_scrape, fake_check
quiet = lambda m: None

pool = pp.ProxyPool("x", want=30, validate_batch=60, validate_deadline=2,
                    refill_backoff=0, logger=quiet)
t = time.time()
pool.warm()
assert time.time() - t < 15, "deadline harus memotong proxy yang menggantung"
assert pool.pool and pool._backlog, "sisa kandidat harus disimpan di backlog"


def work(i, proxy):
    time.sleep(0.2)
    if i % 7 == 0:
        raise pp.ProxyFailure("dead")
    return i * 2


res = pp.map_with_rotation(pool, work, range(50), workers=16, retry_delay=0, logger=quiet)
assert res[1] == 2 and isinstance(res[0], pp.ProxyUnavailable) and isinstance(res[49], Exception)
assert not pool.in_use, "in_use bocor"

# rotasi: dengan 8 proxy, 40 take() harus menyebar, bukan cuma kuartil tercepat
pool.pool = [(f"http://1.1.1.{i}:80", i / 10) for i in range(8)]
used = set()
for _ in range(40):
    p = pool.take(); used.add(p); pool.release(p)
assert len(used) >= 6, f"rotasi sempit: {len(used)} proxy"

# max_latency: proxy lambat tidak masuk pool dan dibanned "slow"
pp.check_proxy = lambda p, *a: (True, 3.0 if p.endswith(".1:80") else 0.1, "")
fast = pp.ProxyPool("x", max_latency=1.0, logger=quiet)
got = fast._validate_batch(["http://2.2.2.1:80", "http://2.2.2.2:80"], 5)
assert [p for p, _ in got] == ["http://2.2.2.2:80"] and fast.cache.is_banned("http://2.2.2.1:80")
print("ok")
