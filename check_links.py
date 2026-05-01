#!/usr/bin/env python3
import sys, os, socket, time, ssl, subprocess, json, signal
from urllib.parse import urlparse, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
import base64

INPUT = "mobile-whitelist-1.txt"
OUTPUT = "working_whitelist.txt"
WORKERS = 12
XRAY = "/usr/local/bin/xray"

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
                "log": {"loglevel": "error"},
                "inbounds": [{"port": 0, "listen": "127.0.0.1", "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}],
                "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": h, "port": port, "users": [{"id": uid, "flow": q.get("flow", [""])[0]}]}]}, "streamSettings": {"network": q.get("type", ["tcp"])[0], "security": sec}}]
            }
            if sec in ("tls", "reality"):
                cfg["outbounds"][0]["streamSettings"]["tlsSettings"] = {"serverName": q.get("sni", [h])[0], "fingerprint": q.get("fp", ["chrome"])[0], "alpn": q.get("alpn", ["h2,http/1.1"])[0].split(",")}
            return cfg, "vless"
        elif link.startswith("trojan://"):
            pwd = unquote(p.username or "")
            cfg = {
                "log": {"loglevel": "error"},
                "inbounds": [{"port": 0, "listen": "127.0.0.1", "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}],
                "outbounds": [{"protocol": "trojan", "settings": {"servers": [{"address": h, "port": port, "password": pwd}]}, "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"serverName": q.get("sni", [h])[0], "alpn": q.get("alpn", ["h2,http/1.1"])[0].split(",")}}}]
            }
            return cfg, "trojan"
        elif link.startswith("ss://"):
            ui = p.username or ""
            try:
                mp = base64.b64decode(ui).decode() if "@" not in ui else ui.split("@")[0]
            except:
                mp = ui
            pts = mp.split(":", 1)
            cfg = {
                "log": {"loglevel": "error"},
                "inbounds": [{"port": 0, "listen": "127.0.0.1", "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}],
                "outbounds": [{"protocol": "shadowsocks", "settings": {"servers": [{"address": h, "port": port, "method": pts[0] if pts else "chacha20-ietf-poly1305", "password": pts[1] if len(pts) > 1 else ""}]}}]
            }
            return cfg, "shadowsocks"
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

def start_xray(cfg, base_port):
    try:
        cfg["inbounds"][0]["port"] = base_port
        cfg_file = f"/tmp/xray_{base_port}.json"
        with open(cfg_file, "w") as f:
            json.dump(cfg, f)
        proc = subprocess.Popen([XRAY, "run", "-config", cfg_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        time.sleep(2)
        return proc, cfg_file
    except:
        return None, None

def http_test(socks_port, timeout):
    try:
        cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-x", f"socks5h://127.0.0.1:{socks_port}", "--connect-timeout", str(timeout), "-m", str(timeout), "https://cp.cloudflare.com"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+2)
        code = result.stdout.strip()
        return code in ("204", "301", "302", "429")
    except:
        return False

def test_proxy(link, base_port):
    result = {"link": link, "ok": False, "latency": 0, "reason": ""}
    cfg, proto = parse_link(link)
    if not cfg:
        result["reason"] = "parse"
        return result
    try:
        if proto == "vless":
            h = cfg["outbounds"][0]["settings"]["vnext"][0]["address"]
            p = cfg["outbounds"][0]["settings"]["vnext"][0]["port"]
        elif proto == "trojan":
            h = cfg["outbounds"][0]["settings"]["servers"][0]["address"]
            p = cfg["outbounds"][0]["settings"]["servers"][0]["port"]
        else:
            h = cfg["outbounds"][0]["settings"]["servers"][0]["address"]
            p = cfg["outbounds"][0]["settings"]["servers"][0]["port"]
    except:
        result["reason"] = "extract"
        return result
    ok, lat = tcp_check(h, p, 2.5)
    if not ok or lat is None or lat > 700:
        result["reason"] = "tcp"
        return result
    result["latency"] = lat
    proc, cfg_file = start_xray(cfg, base_port)
    if not proc:
        result["reason"] = "xray_start"
        return result
    try:
        if http_test(base_port, 6.0):
            result["ok"] = True
            result["reason"] = "http_ok"
        else:
            result["reason"] = "http_fail"
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except:
            try:
                os.kill(proc.pid, signal.SIGKILL)
            except:
                pass
        try:
            os.remove(cfg_file)
        except:
            pass
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
        print(f"Checking {len(links)} proxies (TCP+TLS+HTTP)...")
        working = []
        with ThreadPoolExecutor(max_workers=WORKERS) as ex:
            futs = {ex.submit(test_proxy, ln, 12000 + i): ln for i, ln in enumerate(links)}
            for fut in as_completed(futs):
                r = fut.result()
                pv = r["link"][:45] + "..." if len(r["link"]) > 45 else r["link"]
                if r["ok"]:
                    working.append(r)
                    print(f"OK ({r['latency']}ms): {pv} [{r['reason']}]")
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
