#!/usr/bin/env python3
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

INPUT_FILE = "mobile-whitelist-1.txt"
OUTPUT_FILE = "working_whitelist.txt"

# ==================== НАСТРОЙКИ ====================
MAX_WORKERS = 7
TCP_TIMEOUT = 5
HTTP_TIMEOUT = 7          # увеличил специально для HTTP-теста
MAX_LATENCY_MS = 2500     # более строгое качество
MAX_HTTP_ATTEMPTS = 2
TEST_URL = "https://cp.cloudflare.com"
# ===================================================

def parse_host_port(link: str):
    """Извлекает host и port из ссылки"""
    try:
        if link.startswith(("vless://", "trojan://")):
            without_scheme = link.split("://", 1)[1]
            at_idx = without_scheme.rfind("@")
            after_at = without_scheme[at_idx + 1:].split("?")[0].split("#")[0]
            if ":" in after_at:
                host, port = after_at.rsplit(":", 1)
                return host.strip("[]"), int(port)

        elif link.startswith("ss://"):
            part = link[5:].split("#")[0].split("@")[-1]
            if ":" in part:
                host, port = part.rsplit(":", 1)
                return host.strip("[]"), int(port)
    except Exception:
        pass
    return None, None

def test_tcp(link: str):
    """TCP-проверка"""
    host, port = parse_host_port(link)
    if not host or not port:
        return None

    start = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TCP_TIMEOUT)
        result = sock.connect_ex((host, port))
        sock.close()
        latency = round((time.time() - start) * 1000, 1)

        if result == 0 and latency <= MAX_LATENCY_MS:
            return {"link": link, "host": host, "port": port, "latency": latency}
    except Exception:
        pass
    return None

def test_http(link_info: dict) -> bool:
    """HTTP-тест на cp.cloudflare.com"""
    for attempt in range(1, MAX_HTTP_ATTEMPTS + 1):
        try:
            cmd = [
                "timeout", str(HTTP_TIMEOUT + 4),
                "curl", 
                "-x", f"socks5h://{link_info['host']}:{link_info['port']}",
                "-I", "--max-time", str(HTTP_TIMEOUT), 
                "-s", "-k", "-o", "/dev/null",
                "-w", "%{http_code}", 
                TEST_URL
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=HTTP_TIMEOUT + 6)
            
            http_code = result.stdout.strip()
            if http_code in ("200", "301", "302", "403", "000"):
                return True
                
            print(f"   Попытка {attempt}/{MAX_HTTP_ATTEMPTS} — код {http_code}")
            
        except Exception:
            print(f"   Попытка {attempt}/{MAX_HTTP_ATTEMPTS} — ошибка")
        
        if attempt < MAX_HTTP_ATTEMPTS:
            time.sleep(1.0)
    
    return False

def main():
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        links = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    print(f"🔍 Запуск проверки: TCP + HTTP (cp.cloudflare.com)")
    print(f"Всего ссылок: {len(links)}\n")

    # Этап 1: TCP
    candidates = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(test_tcp, link): link for link in links}
        for future in as_completed(futures):
            result = future.result()
            if result:
                candidates.append(result)
                print(f"✅ TCP OK ({result['latency']} мс) — {result['host']}:{result['port']}")

    print(f"\nПорт открыт у {len(candidates)} ссылок. Начинаем HTTP-тест...\n")

    # Этап 2: HTTP
    working = []
    for i, candidate in enumerate(candidates, 1):
        print(f"[{i}/{len(candidates)}] Тест {TEST_URL} → {candidate['host']}:{candidate['port']}")
        if test_http(candidate):
            working.append(candidate)
            print("   → УСПЕШНО\n")
        else:
            print("   → Не прошёл\n")
        time.sleep(0.6)

    working.sort(key=lambda x: x["latency"])

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for item in working:
            f.write(item["link"] + "\n")

    print(f"\n{'='*70}")
    print(f"ФИНАЛЬНЫЙ РЕЗУЛЬТАТ: {len(working)} рабочих ссылок из {len(links)}")
    print(f"{'='*70}")

if __name__ == "__main__":
    main()
