#!/usr/bin/env python3
import sys, os, socket, time, ssl
from urllib.parse import urlparse, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
import base64

# ───────── НАСТРОЙКИ ─────────
INPUT = "mobile-whitelist-1.txt"
OUTPUT = "working_whitelist.txt"
MAX_WORKERS = 10
TEST_TIMEOUT = 3
MAX_LATENCY_MS = 3000
# ─────────────────────────────

def parse_link(link):
    try:
        p = urlparse(link)
        q = parse_qs(p.query)
        h = p.hostname
        port = p.port
        if not h or not port:
            return None, None
        if link.startswith("vless://"):
            uid = p.username or ""
            sec = q.get("security", ["none"])[0]
            cfg = {
                "protocol": "vless",
                "settings": {"vnext": [{"address": h, "port": port, "users": [{"id": uid, "flow": q.get("flow", [""])[0]}]}]},
                "streamSettings": {"network": q.get("type", ["tcp"])[0], "security": sec}
            }
            if sec in ("tls", "reality"):
                cfg["streamSettings"]["tlsSettings"] = {
                    "serverName": q.get("sni", [h])[0],
                    "fingerprint": q.get("fp", ["chrome"])[0],
                    "alpn": q.get("alpn", ["h2,http/1.1"])[0].split(",")
                }
            return cfg, "vless"
        elif link.startswith("trojan://"):
            pwd = unquote(p.username or "")
            return {
                "protocol": "trojan",
                "settings": {"servers": [{"address": h, "port": port, "password": pwd}]},
                "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"serverName": q.get("sni", [h])[0], "alpn": q.get("alpn", ["h2,http/1.1"])[0].split(",")}}
            }, "trojan"
        elif link.startswith("ss://"):
            ui = p.username or ""
            try:
                mp = base64.b64decode(ui).decode() if "@" not in ui else ui.split("@")[0]
            except:
                mp = ui
            pts = mp.split(":", 1)
            return {
                "protocol": "shadowsocks",
                "settings": {"servers": [{"address": h, "port": port, "method": pts[0] if pts else "chacha20-ietf-poly1305", "password": pts[1] if len(pts) > 1 else ""}]}
            }, "shadowsocks"
    except:
        pass
    return None, None

def tcp_check(h, port, timeout):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        t0 = time.time()
        r = s.connect_ex((h, port))
        lat = round((time.time() - t0) * 1000, 1)
        s.close()
        return r == 0, lat
    except:
        return False, None

def tls_check(h, port, timeout):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((h, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=h) as ssock:
                return True
    except:
        return False

def test_proxy(link, port):
    result = {"link": link, "ok": False, "latency": 0, "reason": ""}
    cfg, proto = parse_link(link)
    if not cfg:
        result["reason"] = "parse"
        return result
    try:
        if proto == "vless":
            h = cfg["settings"]["vnext"][0]["address"]
            p = cfg["settings"]["vnext"][0]["port"]
        else:
            h = cfg["settings"]["servers"][0]["address"]
            p = cfg["settings"]["servers"][0]["port"]
    except:
        result["reason"] = "extract"
        return result
    
    # TCP проверка с таймаутом
    ok, lat = tcp_check(h, p, TEST_TIMEOUT)
    if not ok or lat is None:
        result["reason"] = "tcp"
        return result
    
    # Проверка пинга
    if lat > MAX_LATENCY_MS:
        result["reason"] = "slow"
        result["latency"] = lat
        return result
    
    result["latency"] = lat
    
    # TLS проверка с таймаутом
    if not tls_check(h, p, TEST_TIMEOUT):
        result["reason"] = "tls"
        return result
    
    result["ok"] = True
    result["reason"] = "ok"
    return result

def main():
    try:
        if not os.path.exists(INPUT):
            print(f"File {INPUT} not found")
            open(OUTPUT, "w").close()
            return
        with open(INPUT, "r", encoding="utf-8") as f:
            links = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        if not links:
            print("No links")
            open(OUTPUT, "w").close()
            return
        print(f"Checking {len(links)} proxies...")
        print(f"Settings: workers={MAX_WORKERS}, timeout={TEST_TIMEOUT}s, max_latency={MAX_LATENCY_MS}ms")
        working = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futs = {ex.submit(test_proxy, ln, 12000 + i): ln for i, ln in enumerate(links)}
            for fut in as_completed(futs):
                r = fut.result()
                pv = r["link"][:45] + "..." if len(r["link"]) > 45 else r["link"]
                if r["ok"]:
                    working.append(r)
                    print(f"OK ({r['latency']}ms): {pv}")
                else:
                    print(f"FAIL: {pv} | {r['reason']}")
        working.sort(key=lambda x: x["latency"])
        with open(OUTPUT, "w", encoding="utf-8") as f:
            for it in working:
                f.write(it["link"] + "\n")
        print(f"\nDone. Working: {len(working)}/{len(links)}")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if not os.path.exists(OUTPUT):
            open(OUTPUT, "w").close()
        sys.exit(0)

if __name__ == "__main__":
    main()
