#!/usr/bin/env python3
import sys, os, socket, time, subprocess, json, signal, base64, shutil
from urllib.parse import urlparse, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

# ==================== МОБИЛЬНЫЕ НАСТРОЙКИ ====================
INPUT = "mobile-whitelist-1.txt"
OUTPUT = "working_whitelist.txt"

# Используем стандартный Android-чек. Он легкий и быстрый.
CHECK_URL = "http://connectivitycheck.gstatic.com/generate_204"

WORKERS = 20      
TIMEOUT_TCP = 1.5  # Если сервер не ответил за 1.5 сек, на мобиле он будет тупить
TIMEOUT_XRAY = 2.0 
TIMEOUT_HTTP = 3.0 # Максимум 5 секунд на полную загрузку через прокси

START_PORT = 14000 
# =============================================================

XRAY_PATH = shutil.which("xray") or "./xray"

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

        # Базовые настройки для TLS (важно для обхода мобильных блокировок)
        tls_settings = {
            "serverName": q.get("sni", [h])[0],
            "fingerprint": q.get("fp", ["chrome"])[0], # Эмуляция браузера
            "alpn": ["h2", "http/1.1"]
        }

        if link.startswith("vless://"):
            sec = q.get("security", ["none"])[0]
            v_out = {
                "protocol": "vless",
                "settings": {"vnext": [{"address": h, "port": port, "users": [{"id": p.username or "", "flow": q.get("flow", [""])[0], "encryption": "none"}]}]},
                "streamSettings": {"network": q.get("type", ["tcp"])[0], "security": sec}
            }
            if sec == "tls":
                v_out["streamSettings"]["tlsSettings"] = tls_settings
            elif sec == "reality":
                v_out["streamSettings"]["realitySettings"] = {
                    "show": False,
                    "fingerprint": "chrome",
                    "serverName": q.get("sni", [h])[0],
                    "publicKey": q.get("pbk", [""])[0],
                    "shortId": q.get("sid", [""])[0],
                    "spiderX": "/"
                }
            cfg["outbounds"].append(v_out)
        elif link.startswith("ss://"):
            ui = p.username or ""
            try:
                decoded = base64.b64decode(ui + "==").decode()
                method, passwd = decoded.split(":", 1)
            except: method, passwd = "chacha20-ietf-poly1305", ui
            cfg["outbounds"].append({
                "protocol": "shadowsocks",
                "settings": {"servers": [{"address": h, "port": port, "method": method, "password": passwd}]}
            })
        elif link.startswith("trojan://"):
            cfg["outbounds"].append({
                "protocol": "trojan",
                "settings": {"servers": [{"address": h, "port": port, "password": unquote(p.username or "")}]},
                "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": tls_settings}
            })
        else: return None, None
        return cfg, "ok"
    except: return None, None

def http_test(port):
    try:
        # Добавлен User-Agent, чтобы не палиться перед DPI
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        cmd = ["curl", "-sL", "-o", "/dev/null", "-w", "%{http_code}", 
               "-A", user_agent,
               "-x", f"socks5h://127.0.0.1:{port}", 
               "--connect-timeout", "3", 
               "-m", str(TIMEOUT_HTTP), CHECK_URL]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_HTTP + 1)
        return res.stdout.strip() in ("204", "200")
    except: return False

def test_proxy(link, port):
    res = {"link": link, "ok": False, "lat": 0, "msg": "fail"}
    cfg, status = parse_link(link)
    if not cfg: return {**res, "msg": "parse_err"}

    # 1. TCP чек
    try:
        out = cfg["outbounds"][0]["settings"].get("vnext", cfg["outbounds"][0]["settings"].get("servers"))[0]
        start_t = time.time()
        socket.create_connection((out["address"], out["port"]), timeout=TIMEOUT_TCP).close()
        res["lat"] = round((time.time() - start_t) * 1000)
    except: return {**res, "msg": "timeout"}

    # 2. Запуск Xray
    cfg["inbounds"][0]["port"] = port
    cfg_file = f"/tmp/xr_mob_{port}.json"
    with open(cfg_file, "w") as f: json.dump(cfg, f)
    
    try:
        p = subprocess.Popen([XRAY_PATH, "run", "-config", cfg_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(TIMEOUT_XRAY)
        
        if http_test(port):
            res["ok"], res["msg"] = True, "active"
        
        p.terminate()
        p.wait(timeout=1)
    except: pass
    finally:
        if os.path.exists(cfg_file): os.remove(cfg_file)
    return res

def main():
    subprocess.run(["pkill", "-f", "xray"], stderr=subprocess.DEVNULL)
    if not os.path.exists(INPUT):
        print(f"Файл {INPUT} не найден!"); return
    
    with open(INPUT, "r") as f:
        links = [l.strip() for l in f if "://" in l]

    print(f"Мобильная проверка: {len(links)} ссылок. Потоков: {WORKERS}")
    working = []
    
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = {ex.submit(test_proxy, links[i], START_PORT + i): i for i in range(len(links))}
        for f in as_completed(futs):
            r = f.result()
            marker = "📱" if r["ok"] else "✖️"
            if r["ok"]:
                working.append(r)
                print(f"{marker} {r['lat']}ms | {r['link'][:50]}...")
            else:
                pass # Не засоряем экран плохими ссылками

    working.sort(key=lambda x: x["lat"])
    with open(OUTPUT, "w") as f:
        for w in working: f.write(w["link"] + "\n")
    print(f"\nГотово! Найдено для мобильного: {len(working)}")

if __name__ == "__main__":
    main()
