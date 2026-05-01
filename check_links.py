#!/usr/bin/env python3
import sys, os, socket, time, subprocess, json, signal, base64, shutil
from urllib.parse import urlparse, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─────────── БЛОК НАСТРОЕК ───────────
INPUT = "mobile-whitelist-1.txt"
OUTPUT = "working_whitelist.txt"

# Авто-поиск Xray: сначала в текущей папке, потом в системе
XRAY = "./xray" if os.path.exists("./xray") else shutil.which("xray")

WORKERS = 30
TIMEOUT_TCP = 2.0      
TIMEOUT_XRAY_WAIT = 2.0 
TIMEOUT_HTTP = 5.0      
TEST_URL = "http://connectivitycheck.gstatic.com/generate_204"
# ─────────────────────────────────────

def parse_link(link):
    try:
        p = urlparse(link)
        q = parse_qs(p.query)
        h, port = p.hostname, p.port
        if not h or not port: return None, None
        
        cfg = {
            "log": {"loglevel": "error"},
            "inbounds": [{"port": 0, "listen": "127.0.0.1", "protocol": "socks", "settings": {"auth": "noauth", "udp": True}}],
            "outbounds": []
        }

        # VLESS
        if link.startswith("vless://"):
            sec = q.get("security", ["none"])[0]
            v_out = {
                "protocol": "vless",
                "settings": {"vnext": [{"address": h, "port": port, "users": [{"id": p.username or "", "flow": q.get("flow", [""])[0], "encryption": "none"}]}]},
                "streamSettings": {"network": q.get("type", ["tcp"])[0], "security": sec}
            }
            if sec in ("tls", "reality"):
                v_out["streamSettings"]["tlsSettings"] = {
                    "serverName": q.get("sni", [h])[0],
                    "fingerprint": q.get("fp", ["chrome"])[0]
                }
                if sec == "reality":
                    v_out["streamSettings"]["realitySettings"] = {"publicKey": q.get("pbk", [""])[0], "shortId": q.get("sid", [""])[0]}
            cfg["outbounds"].append(v_out)
            return cfg, "vless"

        # TROJAN
        elif link.startswith("trojan://"):
            cfg["outbounds"].append({
                "protocol": "trojan",
                "settings": {"servers": [{"address": h, "port": port, "password": unquote(p.username or "")}]},
                "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"serverName": q.get("sni", [h])[0]}}
            })
            return cfg, "trojan"

        # SHADOWSOCKS
        elif link.startswith("ss://"):
            ui = p.username or ""
            try:
                # Декодируем метод и пароль из base64
                decoded = base64.b64decode(ui + "==").decode()
                method, passwd = decoded.split(":", 1)
            except: method, passwd = "chacha20-ietf-poly1305", ui
            cfg["outbounds"].append({
                "protocol": "shadowsocks",
                "settings": {"servers": [{"address": h, "port": port, "method": method, "password": passwd}]}
            })
            return cfg, "ss"
            
    except Exception as e: pass
    return None, None

def http_test(socks_port):
    try:
        cmd = ["curl", "-sL", "-o", "/dev/null", "-w", "%{http_code}",
               "-x", f"socks5h://127.0.0.1:{socks_port}",
               "--connect-timeout", "3", "-m", str(TIMEOUT_HTTP), TEST_URL]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_HTTP+1)
        return res.stdout.strip() in ("200", "204")
    except: return False

def test_proxy(link, port):
    res = {"link": link, "ok": False, "lat": 0}
    cfg, proto = parse_link(link)
    if not cfg: return res

    # 1. TCP Check
    try:
        # Универсальный способ достать адрес и порт из конфига
        out = cfg["outbounds"][0]["settings"].get("vnext", cfg["outbounds"][0]["settings"].get("servers"))[0]
        addr = out.get("address") or out.get("host")
        p = out.get("port")
        
        t0 = time.time()
        socket.create_connection((addr, p), timeout=TIMEOUT_TCP).close()
        res["lat"] = round((time.time() - t0) * 1000)
    except: return res

    # 2. Xray Check
    if not XRAY: return res # Если xray не найден, всё упадет
    
    cfg["inbounds"][0]["port"] = port
    cfg_file = f"/tmp/xr_{port}.json"
    with open(cfg_file, "w") as f: json.dump(cfg, f)
    
    try:
        p = subprocess.Popen([XRAY, "run", "-config", cfg_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(TIMEOUT_XRAY_WAIT)
        if http_test(port): res["ok"] = True
        p.terminate()
        p.wait(timeout=1)
    except: pass
    finally:
        if os.path.exists(cfg_file): os.remove(cfg_file)
    return res

def main():
    if not XRAY:
        print("❌ ОШИБКА: Файл xray не найден ни в папке, ни в системе!")
        return

    subprocess.run(["pkill", "-f", "xray"], stderr=subprocess.DEVNULL)
    if not os.path.exists(INPUT): return
    with open(INPUT, "r") as f:
        links = list(set([l.strip() for l in f if "://" in l]))

    print(f"🔍 Начинаем проверку {len(links)} ссылок...")
    working = []
    
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = {ex.submit(test_proxy, links[i], 12000 + i): i for i in range(len(links))}
        for f in as_completed(futs):
            r = f.result()
            if r["ok"]:
                working.append(r)
                print(f"✅ {r['lat']}ms | {r['link'][:50]}...")

    working.sort(key=lambda x: x["lat"])
    with open(OUTPUT, "w") as f:
        for it in working: f.write(it["link"] + "\n")
    print(f"\n✨ Готово! Рабочих: {len(working)}")

if __name__ == "__main__":
    main()
