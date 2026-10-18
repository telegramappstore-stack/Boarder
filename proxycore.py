"""proxycore - find and test free proxies, and export them as links.

Pure standard library (no Kivy), so it can be tested on a PC and keeps the APK small.
"""
import ipaddress
import json
import random
import re
import socket
import ssl
import struct
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

# A proxy is "working" only if it can fetch this URL and return HTTP 204 (no body to fake).
TEST_TARGET = ("www.gstatic.com", 80, "/generate_204")

# Each entry is a group of mirrors for the same list; the first mirror that answers is used.
# jsDelivr mirrors the same GitHub files and is often reachable when raw.githubusercontent.com is not.
SOURCES = {
    "socks5": [
        ("https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
         "https://cdn.jsdelivr.net/gh/TheSpeedX/PROXY-List@master/socks5.txt"),
        ("https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
         "https://cdn.jsdelivr.net/gh/hookzof/socks5_list@master/proxy.txt"),
        ("https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
         "https://cdn.jsdelivr.net/gh/monosans/proxy-list@main/proxies/socks5.txt"),
    ],
    "http": [
        ("https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
         "https://cdn.jsdelivr.net/gh/TheSpeedX/PROXY-List@master/http.txt"),
        ("https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
         "https://cdn.jsdelivr.net/gh/monosans/proxy-list@main/proxies/http.txt"),
    ],
}


class Proxy:
    __slots__ = ("kind", "host", "port", "ms")

    def __init__(self, kind, host, port, ms=None):
        self.kind, self.host, self.port, self.ms = kind, host, int(port), ms

    @property
    def addr(self):
        return "%s:%d" % (self.host, self.port)

    def to_dict(self):
        return {"kind": self.kind, "host": self.host, "port": self.port, "ms": self.ms}


# ------------------------------------------------------------------ parsing / fetching
_ADDR = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})(?!\d)")


def parse_proxies(text, kinds=("socks5", "http")):
    """Extract ip:port pairs. A 'socks'/'http' word on the line decides the type, else `kinds` are all tried.
    Private / loopback / link-local addresses are skipped on purpose (a list must not make the phone scan your LAN)."""
    out, seen = [], set()
    for line in text.splitlines():
        m = _ADDR.search(line)
        if not m:
            continue
        host, port = m.group(1), int(m.group(2))
        try:
            if not ipaddress.ip_address(host).is_global:
                continue
        except ValueError:
            continue
        if not 1 <= port <= 65535:
            continue
        low = line.lower()
        ks = ["socks5"] if "socks" in low else ["http"] if "http" in low else list(kinds)
        for k in ks:
            if (k, host, port) not in seen:
                seen.add((k, host, port))
                out.append(Proxy(k, host, port))
    return out


def _ssl_context():
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


def fetch_text(url, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout, context=_ssl_context()) as r:
        return r.read(3_000_000).decode("utf-8", "ignore")


def fetch_candidates(kinds, log=lambda m: None, stop=None):
    out, seen = [], set()
    for kind in kinds:
        for mirrors in SOURCES.get(kind, []):
            for url in mirrors:
                if stop is not None and stop.is_set():
                    return out
                host = url.split("/")[2]
                try:
                    items = parse_proxies(fetch_text(url), (kind,))
                except Exception as e:
                    log("%s unavailable (%s)" % (host, type(e).__name__))
                    continue
                new = [p for p in items if (p.kind, p.host, p.port) not in seen]
                seen.update((p.kind, p.host, p.port) for p in new)
                out.extend(new)
                log("%s: %d %s proxies" % (host, len(new), kind))
                break
    return out


def pick_sample(cands, limit):
    """Random sample that keeps the proxy types balanced."""
    by = {}
    for p in cands:
        by.setdefault(p.kind, []).append(p)
    per = max(1, limit // max(1, len(by)))
    out = []
    for lst in by.values():
        random.shuffle(lst)
        out += lst[:per]
    random.shuffle(out)
    return out


# ------------------------------------------------------------------ testing
def _recvn(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def _status_line(s):
    buf = b""
    while b"\n" not in buf and len(buf) < 512:
        chunk = s.recv(256)
        if not chunk:
            break
        buf += chunk
    return buf.split(b"\n", 1)[0]


def _request(host, path, port):
    hh = host if port == 80 else "%s:%d" % (host, port)
    return ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
            % (path, hh)).encode()


def check_socks5(host, port, timeout=6.0, target=TEST_TARGET):
    th, tp, path = target
    t0 = time.monotonic()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return None
    try:
        s.settimeout(timeout)
        s.sendall(b"\x05\x01\x00")                                   # no-auth only
        if _recvn(s, 2) != b"\x05\x00":
            return None
        hb = th.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + struct.pack(">H", tp))
        head = _recvn(s, 4)
        if len(head) < 4 or head[0] != 5 or head[1] != 0:
            return None
        atyp = head[3]
        if atyp == 1:
            _recvn(s, 6)
        elif atyp == 4:
            _recvn(s, 18)
        elif atyp == 3:
            _recvn(s, _recvn(s, 1)[0] + 2)
        else:
            return None
        s.sendall(_request(th, path, tp))
        if b" 204" not in _status_line(s):
            return None
        return int((time.monotonic() - t0) * 1000)
    except (OSError, IndexError, ValueError):
        return None
    finally:
        try:
            s.close()
        except OSError:
            pass


def check_http(host, port, timeout=6.0, target=TEST_TARGET):
    th, tp, path = target
    t0 = time.monotonic()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return None
    try:
        s.settimeout(timeout)
        url = "http://%s%s%s" % (th, "" if tp == 80 else ":%d" % tp, path)
        s.sendall(_request(th, url, tp))                             # absolute-URI form for proxies
        line = _status_line(s)
        if not line.startswith(b"HTTP/") or b" 204" not in line:
            return None
        return int((time.monotonic() - t0) * 1000)
    except (OSError, ValueError):
        return None
    finally:
        try:
            s.close()
        except OSError:
            pass


def test_many(proxies, on_result, stop, workers=48, timeout=6.0, target=TEST_TARGET):
    """Test proxies in parallel; calls on_result(proxy, ok) from worker context as results arrive."""
    def job(p):
        if stop.is_set():
            return p, None
        fn = check_socks5 if p.kind == "socks5" else check_http
        return p, fn(p.host, p.port, timeout, target)

    ex = ThreadPoolExecutor(max_workers=workers)
    try:
        futs = [ex.submit(job, p) for p in proxies]
        for f in as_completed(futs):
            if stop.is_set():
                break
            p, ms = f.result()
            if ms is not None:
                p.ms = ms
            on_result(p, ms is not None)
    finally:
        ex.shutdown(wait=False, cancel_futures=True)


# ------------------------------------------------------------------ export
def tg_link(p):
    """Telegram only accepts SOCKS5 (and MTProto) proxies through links."""
    return "tg://socks?server=%s&port=%d" % (p.host, p.port) if p.kind == "socks5" else None


def tg_web_link(p):
    return "https://t.me/socks?server=%s&port=%d" % (p.host, p.port) if p.kind == "socks5" else None


def plain_link(p):
    return "%s://%s:%d" % ("socks5" if p.kind == "socks5" else "http", p.host, p.port)


def v2ray_link(p):
    return "%s://%s:%d#%s" % ("socks" if p.kind == "socks5" else "http", p.host, p.port,
                              "%s-%dms" % (p.kind, p.ms or 0))


def export_text(proxies, fmt):
    fn = {"tg": tg_web_link, "v2ray": v2ray_link, "plain": plain_link}[fmt]
    return "\n".join(x for x in (fn(p) for p in proxies) if x)


def save_results(path, proxies):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump([p.to_dict() for p in proxies], f)
    except OSError:
        pass


def load_results(path):
    try:
        with open(path, encoding="utf-8") as f:
            return [Proxy(d["kind"], d["host"], d["port"], d.get("ms")) for d in json.load(f)]
    except (OSError, ValueError, KeyError, TypeError):
        return []
