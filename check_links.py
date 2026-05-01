#!/usr/bin/env python3
import sys, os, socket, time, subprocess, json, signal, base64
from urllib.parse import urlparse, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─────────── БЛОК НАСТРОЕК (МЕНЯЙ ТУТ) ───────────
INPUT = "mobile-whitelist-1.txt"
OUTPUT = "working_whitelist.txt"
XRAY = "/usr/local/bin/xray"

WORKERS = 20           # Количество потоков

# Тайм-ауты
TIMEOUT_TCP = 2.0      # Проверка порта (пинг)
TIMEOUT_XRAY_WAIT = 1.5 # Сколько ждать запуска Xray перед тестом
TIMEOUT_HTTP = 3.0      # Ожидание ответа от сайта (самый важный для мобил)

# Проверка через этот адрес (Android check)
TEST_URL = "http://connectivitycheck.gstatic.com/generate_204"
# ─────────────────────────────────────────────────

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
                "settings": {"vnext": [{"address": h, "port": port, "users": [{"id": p.username or "", "flow": q.get("flow", [""])[0]}]}]},
                "streamSettings": {"network": q.get("type", ["tcp"])[0], "security": sec}
            }
            if sec in ("tls", "reality"):
                v_out["streamSettings"]["tlsSettings"] = {
                    "serverName": q.get("sni", [h])[0],
                    "fingerprint": q.get("fp", ["chrome"])[0],
                    "alpn": q.get("alpn", ["h2,http/1.1"])[0].split(",")
                }
                if sec == "reality":
                    v_out["streamSettings"]["realitySettings"] = {
                        "publicKey": q.get("pbk", [""])[0], 
                        "shortId": q.get("sid", [""])[0]
                    }
            cfg["outbounds"].append(v_out)
            return cfg, "vless"
        # Можно добавить elif для ss и trojan
    except: pass
    return None, None

def http_test(socks_port):
    try:
        # Используем глобальный TIMEOUT_HTTP
        cmd = [
            "curl", "-sL", "-o", "/dev/null", "-w", "%{http_code}",
            "-x", f"socks5h://127.0.0.1:{socks_port}",
            "--connect-timeout", str(int(TIMEOUT_HTTP/2)), 
            "-m", str(TIMEOUT_HTTP),
            TEST_URL
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_HTTP+1)
        code = result.stdout.strip()
        return code in ("200", "204", "301", "302")
    except:
        return False

def test_proxy(link, base_port):
    result = {"link": link, "ok": False, "latency": 0}
    cfg, proto = parse_link(link)
    if not cfg: return result

    # 1. TCP чек (используем TIMEOUT_TCP)
    try:
        out = cfg["outbounds"][0]["settings"].get("vnext", [{}])[0]
        if not out: return result
        t0 = time.time()
        socket.create_connection((out["address"], out["port"]), timeout=TIMEOUT_TCP).close()
        result["latency"] = round((time.time() - t0) * 1000)
    except: return result

    # 2. Xray запуск и HTTP тест
    cfg["inbounds"][0]["port"] = base_port
    cfg_file = f"/tmp/xr_{base_port}.json"
    with open(cfg_file, "w") as f: json.dump(cfg, f)
    
    try:
        proc = subprocess.Popen([XRAY, "run", "-config", cfg_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(TIMEOUT_XRAY_WAIT) # Используем TIMEOUT_XRAY_WAIT
        
        if http_test(base_port):
            result["ok"] = True
            
        proc.terminate()
        proc.wait(timeout=2)
    except: pass
    finally:
        if os.path.exists(cfg_file): os.remove(cfg_file)
    return result

def main():
    # Предварительно чистим процессы
    subprocess.run(["pkill", "-f", "xray"], stderr=subprocess.DEVNULL)
    
    if not os.path.exists(INPUT):
        print(f"Файл {INPUT} не найден")
        return
        
    with open(INPUT, "r") as f:
        links = [l.strip() for l in f if "://" in l]

    print(f"Запуск проверки: {len(links)} ключей | Потоков: {WORKERS}")
    working = []
    
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = {ex.submit(test_proxy, links[i], 12000 + i): i for i in range(len(links))}
        for fut in as_completed(futs):
            r = fut.result()
            if r["ok"]:
                working.append(r)
                print(f"✅ {r['latency']}ms | {r['link'][:45]}...")
            else:
                # Если нужно видеть ошибки, раскомментируй:
                # print(f"❌ FAIL | {r['link'][:45]}...")
                pass

    working.sort(key=lambda x: x["latency"])
    with open(OUTPUT, "w") as f:
        for it in working: f.write(it["link"] + "\n")
        
    print(f"\n✨ Проверка завершена. Рабочих: {len(working)} из {len(links)}")

if __name__ == "__main__":
    main()
