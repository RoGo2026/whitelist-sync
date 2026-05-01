#!/usr/bin/env python3
import sys, os, socket, time, subprocess, json, signal, base64, shutil
from urllib.parse import urlparse, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- НАСТРОЙКИ ---
INPUT = "mobile-whitelist-1.txt"
OUTPUT = "working_whitelist.txt"
WORKERS = 20  # Немного снизил, чтобы не забивать канал при проверке
CHECK_URL = "https://cp.cloudflare.com"

# Автоматический поиск пути к xray
XRAY_PATH = shutil.which("xray") or "./xray"

def parse_link(link):
    try:
        p = urlparse(link)
        q = parse_qs(p.query)
        h = p.hostname
        port = p.port
        if not h or not port: return None, None
        
        # Общий шаблон конфига
        def get_base_cfg():
            return {
                "log": {"loglevel": "error"},
                "inbounds": [{"port": 0, "listen": "127.0.0.1", "protocol": "socks", "settings": {"auth": "noauth", "udp": True}}],
                "outbounds": []
            }

        if link.startswith("vless://"):
            cfg = get_base_cfg()
            sec = q.get("security", ["none"])[0]
            vless_out = {
                "protocol": "vless",
                "settings": {"vnext": [{"address": h, "port": port, "users": [{"id": p.username or "", "flow": q.get("flow", [""])[0], "encryption": "none"}]}]},
                "streamSettings": {"network": q.get("type", ["tcp"])[0], "security": sec}
            }
            if sec in ("tls", "reality"):
                vless_out["streamSettings"]["tlsSettings"] = {
                    "serverName": q.get("sni", [h])[0],
                    "fingerprint": q.get("fp", ["chrome"])[0],
                    "alpn": q.get("alpn", ["h2,http/1.1"])[0].split(",")
                }
                if sec == "reality":
                    vless_out["streamSettings"]["realitySettings"] = {"publicKey": q.get("pbk", [""])[0], "shortId": q.get("sid", [""])[0]}
            cfg["outbounds"].append(vless_out)
            return cfg, "vless"

        elif link.startswith("ss://"):
            cfg = get_base_cfg()
            ui = p.username or ""
            try:
                decoded = base64.b64decode(ui + "==").decode()
                method, passwd = decoded.split(":", 1)
            except:
                method, passwd = "chacha20-ietf-poly1305", ui
            cfg["outbounds"].append({
                "protocol": "shadowsocks",
                "settings": {"servers": [{"address": h, "port": port, "method": method, "password": passwd}]}
            })
            return cfg, "ss"
            
        elif link.startswith("trojan://"):
            cfg = get_base_cfg()
            cfg["outbounds"].append({
                "protocol": "trojan",
                "settings": {"servers": [{"address": h, "port": port, "password": unquote(p.username or "")}]},
                "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"serverName": q.get("sni", [h])[0]}}
            })
            return cfg, "trojan"
    except: pass
    return None, None

def http_test(socks_port, timeout):
    try:
        # -L (редиректы), -s (тихо), -w (код ответа)
        cmd = ["curl", "-sL", "-o", "/dev/null", "-w", "%{http_code}", 
               "-x", f"socks5h://127.0.0.1:{socks_port}", 
               "--connect-timeout", str(timeout), "-m", str(int(timeout)+2), CHECK_URL]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+5)
        return res.stdout.strip() in ("200", "204", "301", "302")
    except: return False

def test_proxy(link, b_port):
    res = {"link": link, "ok": False, "lat": 0, "msg": "fail"}
    cfg, proto = parse_link(link)
    if not cfg: return {**res, "msg": "parse_err"}

    # Быстрая проверка TCP порта перед запуском Xray
    try:
        out = cfg["outbounds"][0]["settings"].get("vnext", cfg["outbounds"][0]["settings"].get("servers"))[0]
        addr = out.get("address")
        port = out.get("port")
        s = socket.create_connection((addr, port), timeout=2.5)
        t0 = time.time()
        s.close()
        res["lat"] = round((time.time() - t0) * 1000)
    except: return {**res, "msg": "tcp_off"}

    # Запуск Xray
    cfg["inbounds"][0]["port"] = b_port
    tmp_fn = f"/tmp/xr_{b_port}.json"
    with open(tmp_fn, "w") as f: json.dump(cfg, f)
    
    try:
        p = subprocess.Popen([XRAY_PATH, "run", "-config", tmp_fn], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(3) # Даем время на инициализацию
        if http_test(b_port, 7):
            res["ok"], res["msg"] = True, "active"
        p.terminate()
        p.wait(timeout=2)
    except: pass
    finally:
        if os.path.exists(tmp_fn): os.remove(tmp_fn)
    return res

def main():
    if not os.path.exists(INPUT):
        print(f"Файл {INPUT} не найден!"); return
    
    with open(INPUT, "r") as f:
        links = [l.strip() for l in f if l.strip() and "://" in l]

    print(f"Проверка {len(links)} ссылок через {CHECK_URL}...")
    working = []
    
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = {ex.submit(test_proxy, links[i], 13000 + i): i for i in range(len(links))}
        for f in as_completed(futs):
            r = f.result()
            status = "OK" if r["ok"] else "FAIL"
            print(f"[{status}] {r['lat']}ms | {r['link'][:50]}... ({r['msg']})")
            if r["ok"]: working.append(r)

    working.sort(key=lambda x: x["lat"])
    with open(OUTPUT, "w") as f:
        for w in working: f.write(w["link"] + "\n")
    print(f"\nГотово! Рабочих: {len(working)} из {len(links)}")

if __name__ == "__main__":
    main()
