#!/usr/bin/env python3
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

INPUT_FILE = "mobile-whitelist-1.txt"
OUTPUT_FILE = "working_whitelist.txt"

MAX_WORKERS = 12
TCP_TIMEOUT = 10
HTTP_TIMEOUT = 12
MAX_LATENCY_MS = 4500
MAX_HTTP_ATTEMPTS = 3

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
    """Первый этап — TCP проверка"""
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
    """Второй этап — максимально мягкий HTTP-тест (3 попытки)"""
    for attempt in range(1, MAX_HTTP_ATTEMPTS + 1):
        try:
            cmd = [
                "timeout", str(HTTP_TIMEOUT),
                "curl", "-x", f"socks5h://{link_info['host']}:{link_info['port']}",
                "-I", "--max-time", "8", "-s", "-k", "-o", "/dev/null",
                "-w", "%{http_code}", "https://www.cloudflare.com"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=HTTP_TIMEOUT + 5)
            
            http_code = result.stdout.strip()
            if http_code in ("200", "301", "302", "403", "000"):
                return True
                
            print(f"   Попытка {attempt}/{MAX_HTTP_ATTEMPTS} — код {http_code}")
            
        except Exception as e:
            print(f"   Попытка {attempt}/{MAX_HTTP_ATTEMPTS} — ошибка")
        
        time.sleep(1.2)  # пауза между попытками
    
    return False

def main():
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        links = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    print(f"🔍 Запуск проверки: TCP + максимально мягкий HTTP-тест")
    print(f"Всего ссылок: {len(links)}\n")

    # Этап 1: TCP проверка
    candidates = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(test_tcp, link): link for link in links}
        for future in as_completed(futures):
            result = future.result()
            if result:
                candidates.append(result)
                print(f"✅ TCP OK ({result['latency']} мс) — {result['host']}:{result['port']}")

    print(f"\nПорт открыт у {len(candidates)} ссылок. Начинаем HTTP-тест...\n")

    # Этап 2: Мягкий HTTP-тест
    working = []
    for i, candidate in enumerate(candidates, 1):
        print(f"[{i}/{len(candidates)}] HTTP-тест {candidate['host']}:{candidate['port']}")
        if test_http(candidate):
            working.append(candidate)
            print("   → УСПЕШНО ПРОШЁЛ\n")
        else:
            print("   → Не прошёл HTTP-тест\n")
        time.sleep(0.6)

    # Сортируем по скорости
    working.sort(key=lambda x: x["latency"])

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for item in working:
            f.write(item["link"] + "\n")

    print(f"\n{'='*65}")
    print(f"ФИНАЛЬНЫЙ РЕЗУЛЬТАТ: {len(working)} рабочих ссылок из {len(links)}")
    print(f"{'='*65}")

if __name__ == "__main__":
    main()
