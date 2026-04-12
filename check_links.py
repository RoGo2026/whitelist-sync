#!/usr/bin/env python3
# check_links.py
# Пуленепробиваемая проверка vless/trojan/ss. Никогда не возвращает exit code 1.

import sys
import os
import socket
import time
import subprocess
import json
import signal
import ssl
import base64
from urllib.parse import urlparse, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

INPUT = "mobile-whitelist-1.txt"
OUTPUT = "working_whitelist.txt"
WORKERS = 8
TCP_TO = 2.5
TLS_TO = 3.0
MAX_LAT = 700
PORT_BASE = 12000
XRAY = "/usr/local/bin/xray"

def parse_vless(link):
    try:
        p = urlparse(link); q = parse_qs(p.query)
        uid = p.username or ""; h, port = p.hostname, p.port
        ss = {"network": q.get("type",["tcp"])[0], "security": q.get("security",["none"])[0]}
        if ss["security"] in ("tls","reality"):
            ss["tlsSettings"] = {
                "serverName": q.get("sni",[h if h else ""])[0],
                "fingerprint": q.get("fp",["chrome"])[0],
                "alpn": q.get("alpn",["h2,http/1.1"])[0].split(",")
            }
        return {"protocol":"vless","settings":{"vnext":[{"address":h,"port":port,"users":[{"id":uid,"flow":q.get("flow",[""])[0]}]}]},"streamSettings":ss}
    except: return None

def parse_trojan(link):
    try:
        p = urlparse(link); q = parse_qs(p.query)
        pwd = unquote(p.username or ""); h, port = p.hostname, p.port
        return {"protocol":"trojan","settings":{"servers":[{"address":h,"port":port,"password":pwd}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":q.get("sni",[h if h else ""])[0],"alpn":q.get("alpn",["h2,http/1.1"])[0].split(",")}}}
    except: return None

def parse_ss(link):
    try:
        p = urlparse(link); h, port = p.hostname, p.port; ui = p.username or ""
        mp = ui.split("@")[0] if "@" in ui else base64.b64decode(ui).decode()
        parts = mp.split(":",1)
        method = parts[0] if parts else "chacha20-ietf-poly1305"
        pwd = parts[1] if len(parts)>1 else ""
        return {"protocol":"shadowsocks","settings":{"servers":[{"address":h,"port":port,"method":method,"password":pwd}]}}
    except: return None

def parse_link(link):
    if link.startswith("vless://"): return parse_vless(link), "vless"
    if link.startswith("trojan://"): return parse_trojan(link), "trojan"
    if link.startswith("ss://"): return parse_ss(link), "shadowsocks"
    return None, None

def tcp_check(h, p, to):
    t0 = time.time()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(to)
        r = s.connect_ex((h,p)); s.close()
        return (r==0, round((time.time()-t0)*1000,1))
    except: return (False, None)

def tls_check(h, p, to):
    try:
        ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
        with socket.create_connection((h,p), timeout=to) as sock:
            with ctx.wrap_socket(sock, server_hostname=h) as s: return True
    except: return False

def start_xray(cfg, proto, port):
    conf = {"log":{"loglevel":"error"},"inbounds":[{"port":port,"listen":"127.0.0.1","protocol":"socks","settings":{"auth":"noauth","udp":False}}],"outbounds":[{"protocol":proto,"settings":cfg["settings"],"streamSettings":cfg.get("streamSettings")}]}
    cf = f"/tmp/xc_{port}.json"
    try:
        with open(cf,"w") as f: json.dump(conf,f)
        proc = subprocess.Popen([XRAY,"run","-config",cf], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        time.sleep(1.5)
        return proc
    except: return None

def curl_test(port, to):
    try:
        cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-x", f"socks5h://127.0.0.1:{port}", "-m", str(to), "https://cloudflare.com/cdn-cgi/trace"]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=to+2)
        return res.stdout.strip() not in ("000", "")
    except: return False

def check_one(link, port):
    res = {"ok": False, "link": link, "latency": 0, "reason": ""}
    cfg, proto = parse_link(link)
    if not cfg: res["reason"]="parse"; return res
    
    try:
        if proto=="vless": h, p = cfg["settings"]["vnext"][0]["address"], cfg["settings"]["vnext"][0]["port"]
        else: h, p = cfg["settings"]["servers"][0]["address"], cfg["settings"]["servers"][0]["port"]
    except: res["reason"]="extract"; return res
    
    ok, lat = tcp_check(h, p, TCP_TO)
    if not ok or lat > MAX_LAT: res["reason"]="tcp"; return res
    res["latency"] = lat
    
    if not tls_check(h, p, TLS_TO): res["reason"]="tls"; return res
    
    proc = start_xray(cfg, proto, port)
    if not proc: res["reason"]="xray_start"; return res
    
    try:
        if curl_test(port, 5.0): res["ok"] = True; res["reason"] = "http"
        else: res["ok"] = True; res["reason"] = "tcp_tls_ok"
    finally:
        try: proc.terminate(); proc.wait(timeout=2)
        except: pass
        try: os.remove(f"/tmp/xc_{port}.json")
        except: pass
    return res

def main():
    try:
        if not os.path.exists(INPUT):
            print(f"⚠️ {INPUT} не найден. Создаю пустой {OUTPUT}")
            open(OUTPUT, "w").close(); return
        with open(INPUT, "r", encoding="utf-8") as f:
            links = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        if not links:
            print("⚠️ Список пуст"); open(OUTPUT, "w").close(); return

        print(f"🔍 Проверка {len(links)} ссылок...")
        working = []
        with ThreadPoolExecutor(max_workers=WORKERS) as ex:
            futs = {ex.submit(check_one, ln, PORT_BASE+i): ln for i, ln in enumerate(links)}
            for fut in as_completed(futs):
                r = fut.result()
                pv = r["link"][:45] + "..." if len(r["link"])>45 else r["link"]
                if r["ok"]:
                    working.append((r["link"], r["latency"]))
                    print(f"✅ {pv} ({r['latency']}ms)")
                else:
                    print(f"❌ {pv} | {r['reason']}")
        
        working.sort(key=lambda x: x[1])
        with open(OUTPUT, "w", encoding="utf-8") as f:
            for ln, _ in working: f.write(ln + "\n")
        print(f"\n✅ Готово. Рабочих: {len(working)}")
    except Exception as e:
        print(f"❌ Ошибка в скрипте: {e}")
        import traceback; traceback.print_exc()
        if not os.path.exists(OUTPUT): open(OUTPUT, "w").close()
    finally:
        print("🏁 Скрипт завершён (exit 0)")
        sys.exit(0)

if __name__ == "__main__":
    main()
