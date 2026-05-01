#!/usr/bin/env python3
import sys, os, socket, time, subprocess, json, signal, base64, shutil
from urllib.parse import urlparse, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

# ==================== НАСТРОЙКИ (МЕНЯЙТЕ ТУТ) ====================
INPUT = "mobile-whitelist-1.txt"  # Файл с ключами
OUTPUT = "working_whitelist.txt"  # Файл для рабочих ключей
CHECK_URL = "https://www.google.com/generate_204" # Сайт для проверки

WORKERS = 20      # Количество одновременно проверяемых ключей (меньше = стабильнее)

# Тайм-ауты (в секундах)
TIMEOUT_TCP = 2.0  # Ожидание отклика сервера (пинг)
TIMEOUT_XRAY = 1.0 # Сколько ждать запуска ядра Xray перед тестом
TIMEOUT_HTTP = 2.0 # Сколько ждать загрузки страницы (самый важный тайм-аут)

# Порты
START_PORT = 13000 # С какого порта начинать локальные прокси
# =================================================================

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
                    "fingerprint": q.get("fp", ["chrome"])[0],
                    "alpn": q.get("alpn", ["h2,http/1.1"])[0].split(",")
                }
                if sec == "reality":
                    v_out["streamSettings"]["realitySettings"] = {"publicKey": q.get("pbk", [""])[0], "shortId": q.get("sid", [""])[0]}
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
        else: return None, None
        return cfg, "ok"
    except: return None, None

def http_test(port):
    try:
        # -sL (тихо + редиректы), -w (код), -m (макс время всей операции)
        cmd = ["curl", "-sL", "-o", "/dev/null", "-w", "%{http_code}", 
               "-x", f"socks5h://127.0.0.1:{port}", 
               "--connect-timeout", str(int(TIMEOUT_HTTP/2)), 
               "-m", str(TIMEOUT_HTTP), CHECK_URL]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_HTTP + 1)
        # Если сайт вернул 200, 204 или редирект — прокси рабочий
        return res.stdout.strip() in ("200", "204", "301", "302")
    except: return False

def test_proxy(link, port):
    res = {"link": link, "ok": False, "lat": 0, "msg": "fail"}
    cfg, status = parse_link(link)
    if not cfg: return {**res, "msg": "parse_err"}

    # 1. Быстрый TCP чек (пингуем сервер)
    try:
        addr = cfg["outbounds"][0]["settings"].get("vnext", cfg["outbounds"][0]["settings"].get("servers"))[0]["address"]
        srv_port = cfg["outbounds"][0]["settings"].get("vnext", cfg["outbounds"][0]["settings"].get("servers"))[0]["port"]
        start_t = time.time()
        socket.create_connection((addr, srv_port), timeout=TIMEOUT_TCP).close()
        res["lat"] = round((time.time() - start_t) * 1000)
    except: return {**res, "msg": "dead_srv"}

    # 2. Запуск Xray
    cfg["inbounds"][0]["port"] = port
    cfg_file = f"/tmp/xr_{port}.json"
    with open(cfg_file, "w") as f: json.dump(cfg, f)
    
    try:
        p = subprocess.Popen([XRAY_PATH, "run", "-config", cfg_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(TIMEOUT_XRAY) # Ждем прогрузки ядра
        
        if http_test(port):
            res["ok"], res["msg"] = True, "active"
        
        p.terminate() # Сразу убиваем процесс после теста
        p.wait(timeout=1)
    except: pass
    finally:
        if os.path.exists(cfg_file): os.remove(cfg_file)
    return res

def main():
    # Перед началом убиваем старые процессы xray, чтобы порты были свободны
    subprocess.run(["pkill", "-f", "xray"], stderr=subprocess.DEVNULL)
    
    if not os.path.exists(INPUT):
        print(f"Файл {INPUT} не найден!"); return
    
    with open(INPUT, "r") as f:
        links = [l.strip() for l in f if "://" in l]

    print(f"Проверка {len(links)} ссылок. Потоков: {WORKERS}. Тайм-аут: {TIMEOUT_HTTP} сек.")
    working = []
    
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        # Раздаем задачи. Каждый поток получает свой уникальный порт
        futs = {ex.submit(test_proxy, links[i], START_PORT + i): i for i in range(len(links))}
        for f in as_completed(futs):
            r = f.result()
            marker = "✅" if r["ok"] else "❌"
            print(f"{marker} {r['lat']}ms | {r['msg']} | {r['link'][:40]}...")
            if r["ok"]: working.append(r)

    working.sort(key=lambda x: x["lat"])
    with open(OUTPUT, "w") as f:
        for w in working: f.write(w["link"] + "\n")
    print(f"\nГотово! Найдено рабочих: {len(working)}")

if __name__ == "__main__":
    main()
