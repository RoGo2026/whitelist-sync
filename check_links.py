#!/usr/bin/env python3
import sys, os, socket, time, subprocess, json, signal, base64, shutil
import urllib.request
from urllib.parse import urlparse, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

# ==================== НАСТРОЙКИ АВТОМАТИЗАЦИИ ====================
# Ссылка на исходный файл (замени на свою прямую ссылку на raw файл)
SOURCE_URL = "https://gitverse.ru/api/v1/repos/user/repo/raw/mobile-whitelist-1.txt"

INPUT = "mobile-whitelist-1.txt"
OUTPUT = "working_whitelist.txt"

CHECK_URL = "http://connectivitycheck.gstatic.com/generate_204"
XRAY_PATH = shutil.which("xray") or "./xray"

WORKERS = 20
TIMEOUT_HTTP = 3.0
START_PORT = 15000
# =================================================================

def download_source():
    """Скачивает свежий список ключей."""
    print(f"📥 Скачивание списка из источника...")
    try:
        with urllib.request.urlopen(SOURCE_URL, timeout=10) as response:
            content = response.read().decode('utf-8')
            with open(INPUT, "w", encoding="utf-8") as f:
                f.write(content)
        print(f"✅ Файл успешно скачан.")
        return True
    except Exception as e:
        print(f"❌ Ошибка скачивания: {e}")
        return False

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

        # Настройки для обхода DPI мобильных операторов
        tls_settings = {
            "serverName": q.get("sni", [h])[0],
            "fingerprint": q.get("fp", ["chrome"])[0],
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
        return cfg, "ok"
    except: return None, None

def http_test(port):
    try:
        ua = "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36"
        cmd = ["curl", "-sL", "-o", "/dev/null", "-w", "%{http_code}", 
               "-A", ua, "-x", f"socks5h://127.0.0.1:{port}", 
               "--connect-timeout", "3", "-m", str(TIMEOUT_HTTP), CHECK_URL]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_HTTP + 1)
        return res.stdout.strip() in ("204", "200")
    except: return False

def test_proxy(link, port):
    res = {"link": link, "ok": False, "lat": 0}
    cfg, status = parse_link(link)
    if not cfg: return res

    # 1. TCP Check
    try:
        out = cfg["outbounds"][0]["settings"].get("vnext", cfg["outbounds"][0]["settings"].get("servers"))[0]
        st = time.time()
        socket.create_connection((out["address"], out["port"]), timeout=2).close()
        res["lat"] = round((time.time() - st) * 1000)
    except: return res

    # 2. Xray + HTTP Check
    cfg["inbounds"][0]["port"] = port
    tmp = f"/tmp/xr_{port}.json"
    with open(tmp, "w") as f: json.dump(cfg, f)
    
    try:
        p = subprocess.Popen([XRAY_PATH, "run", "-config", tmp], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.5)
        if http_test(port): res["ok"] = True
        p.terminate()
        p.wait(timeout=1)
    except: pass
    finally:
        if os.path.exists(tmp): os.remove(tmp)
    return res

def main():
    # Пред-очистка
    subprocess.run(["pkill", "-f", "xray"], stderr=subprocess.DEVNULL)
    
    # 1. Обновляем исходник
    if not download_source() and not os.path.exists(INPUT):
        return

    # 2. Читаем ключи
    with open(INPUT, "r") as f:
        links = [l.strip() for l in f if "://" in l]

    print(f"🚀 Начинаем проверку {len(links)} ключей...")
    working = []
    
    # 3. Проверка в потоках
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = {ex.submit(test_proxy, links[i], START_PORT + i): i for i in range(len(links))}
        for f in as_completed(futs):
            r = f.result()
            if r["ok"]:
                working.append(r)
                print(f"✅ {r['lat']}ms | {r['link'][:40]}...")

    # 4. Сохранение результата
    working.sort(key=lambda x: x["lat"])
    with open(OUTPUT, "w") as f:
        for w in working: f.write(w["link"] + "\n")
    
    print(f"\n✨ Готово! Рабочих ключей сохранено: {len(working)}")

if __name__ == "__main__":
    main()
