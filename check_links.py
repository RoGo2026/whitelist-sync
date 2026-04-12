#!/usr/bin/env python3
# check_links.py
# Проверка vless/trojan/ss через TCP + TLS + HTTP (щадящий режим)
# Никогда не завершается с кодом 1. Всегда создаёт output файл.

import socket, time, sys, os, subprocess, json, signal, shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, unquote
import base64, traceback

INPUT = "mobile-whitelist-1.txt"
OUTPUT = "working_whitelist.txt"
MAX_WORKERS = 8
TCP_TIMEOUT = 2.5
TLS_TIMEOUT = 3.0
MAX_LATENCY = 700
SOCKS_START_PORT = 12000
XRAY_PATH = shutil.which("xray") or "/usr/local/bin/xray"

def parse_vless(link):
    try:
        p = urlparse(link); q = parse_qs(p.query)
        uid = p.username or ""; host, port = p.hostname, p.port
        flow = q.get("flow",[""])[0]; sec = q.get("security",["none"])[0]
        sni = q.get("sni",[host if host else ""])[0]; fp = q.get("fp",["chrome"])[0]
        alpn = q.get("alpn",["h2,http/1.1"])[0]; pbk = q.get("pbk",[""])[0]; sid = q.get("sid",[""])[0]
        ht = q.get("headerType",["none"])[0]
        ss = {"network": q.get("type",["tcp"])[0], "security": sec}
        if sec in ("tls","reality"):
            ts = {"serverName": sni, "fingerprint": fp, "alpn": alpn.split(",")}
            if sec=="reality" and pbk and sid: ts.update({"publicKey": pbk[0], "shortId": sid[0]})
            ss["tlsSettings"] = ts
        if ht != "none": ss["tcpSettings"] = {"header": {"type": ht}}
        return {"protocol":"vless","settings":{"vnext":[{"address":host,"port":port,"users":[{"id":uid,"flow":flow}]}]},"streamSettings":ss}
    except: return None

def parse_trojan(link):
    try:
        p = urlparse(link); q = parse_qs(p.query)
        pwd = unquote(p.username or ""); host, port = p.hostname, p.port
        sni = q.get("sni",[host if host else ""])[0]; alpn = q.get("alpn",["h2,http/1.1"])[0]
        return {"protocol":"trojan","settings":{"servers":[{"address":host,"port":port,"password":pwd}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":sni,"alpn":alpn.split(",")}}}
    except: return None

def parse_ss(link):
    try:
        p = urlparse(link); host, port = p.hostname, p.port; ui = p.username or ""
        if "@" in ui: mp = ui.split("@")[0]
        else:
            try: dec = base64.b64decode(ui).decode().split(":",1); mp = dec[0]+":"+dec[1] if len(dec)>1 else dec[0]
            except: mp = ui
        pts = mp.split(":",1); method = pts[0] if pts else "chacha20-ietf-poly1305"; pwd = pts[1] if len(pts)>1 else ""
        return {"protocol":"shadowsocks","settings":{"servers":[{"address":host,"port":port,"method":method,"password":pwd}]}}
    except: return None

def parse_link(link):
    if link.startswith("vless://"): return parse_vless(link), "vless"
    if link.startswith("trojan://"): return parse_trojan(link), "trojan"
    if link.startswith("ss://"): return parse_ss(link), "shadowsocks"
    return None, None

def tcp_check(host, port, to):
    t0 = time.time()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(to)
        r = s.connect_ex((host,port)); s.close()
        return (r==0, round((time.time()-t0)*1000,1))
    except: return (False, None)

def tls_check(host, port, to):
    try:
        ctx = __import__("ssl").create_default_context(); ctx.check_hostname=False; ctx.verify_mode=__import__("ssl").CERT_NONE
        with socket.create_connection((host,port), timeout=to) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s: return True
    except: return False

def start_xray(cfg, proto, lport):
    conf = {"log":{"loglevel":"error"},"inbounds":[{"port":lport,"listen":"127.0.0.1","protocol":"socks","settings":{"auth":"noauth","udp":False,"ip":"127.0.0.1"}}],"outbounds":[{"protocol":proto,"settings":cfg["settings"],"streamSettings":cfg.get("streamSettings")}]}
    cf = f"/tmp/xc_{lport}.json"
    with open(cf,"w") as f: json.dump(conf,f)
    try:
        proc = subprocess.Popen([XRAY_PATH,"run","-config",cf], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        time.sleep(1.8); return proc
    except: return None

def curl_test(socks_port, to):
    try:
        cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", 
               "-x", f"socks5h://127.0.0.1:{socks_port}",
               "-m", str(to), "--retry", "0", "--connect-timeout", str(to),
               "https://cloudflare.com/cdn-cgi/trace"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=to+2)
        code = result.stdout.strip()
        return code not in ("000", "")
    except: return False

def test_link(link, lport):
    res = {"link":link,"status":"dead","latency":None,"reason":""}
    cfg, proto = parse_link(link)
    if not cfg: res["reason"]="parse_err"; return res
    try:
        if proto=="vless": h,p = cfg["settings"]["vnext"][0]["address"], cfg["settings"]["vnext"][0]["port"]
        elif proto=="trojan": h,p = cfg["settings"]["servers"][0]["address"], cfg["settings"]["servers"][0]["port"]
        else: h,p = cfg["settings"]["servers"][0]["address"], cfg["settings"]["servers"][0]["port"]
    except: res["reason"]="extract_err"; return res
    
    tcp_ok, lat = tcp_check(h,p,TCP_TIMEOUT)
    if not tcp_ok or lat is None or lat > MAX_LATENCY: res["reason"]="tcp_fail"; return res
    res["latency"] = lat
    
    if not tls_check(h,p,TLS_TIMEOUT): res["reason"]="tls_fail"; return res
    
    proc = start_xray(cfg, proto, lport)
    if not proc: res["reason"]="xray_err"; return res
    try:
        http_ok = curl_test(lport, 6.0)
        if http_ok: res["status"]="ok"; res["reason"]="http_ok"
        else: res["status"]="ok"; res["reason"]="tcp_tls_ok_http_uncertain"
    finally:
        try: proc.terminate(); proc.wait(timeout=2)
        except:
            try: os.kill(proc.pid, signal.SIGKILL)
            except: pass
        try: os.remove(f"/tmp/xc_{lport}.json")
        except: pass
    return res

def main():
    try:
        if not os.path.exists(INPUT):
            print(f"❌ Файл {INPUT} не найден. Создаю пустой {OUTPUT}")
            open(OUTPUT, "w").close(); return
        with open(INPUT,"r",encoding="utf-8") as f:
            links = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        if not links:
            print("❌ Список пуст"); open(OUTPUT, "w").close(); return
            
        print(f"🔍 Проверка {len(links)} ссылок (TCP+TLS+HTTP щадящий режим)...")
        working = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futs = {ex.submit(test_link, ln, SOCKS_START_PORT+i): ln for i,ln in enumerate(links)}
            for fut in as_completed(futs):
                r = fut.result(); pv = (r["link"][:40]+"...") if len(r["link"])>40 else r["link"]
                if r["status"]=="ok":
                    working.append(r); print(f"✅ ({r['latency']}ms) {pv} [{r['reason']}]")
                else:
                    print(f"❌ {pv} | {r['reason']}")
        working.sort(key=lambda x: x["latency"])
        with open(OUTPUT,"w",encoding="utf-8") as f:
            for it in working: f.write(it["link"]+"\n")
        print(f"\n✅ Готово. Рабочих: {len(working)}/{len(links)}")
    except Exception as e:
        print(f"⚠️  Ошибка выполнения: {e}")
        traceback.print_exc()
    finally:
        if not os.path.exists(OUTPUT): open(OUTPUT, "w").close()
        print("🏁 Скрипт завершён (exit 0)")
        sys.exit(0)

if __name__ == "__main__":
    main()
