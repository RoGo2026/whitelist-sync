#!/usr/bin/env python3
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

INPUT_FILE = "mobile-whitelist-1.txt"
OUTPUT_FILE = "working_whitelist.txt"

MAX_WORKERS = 10
TCP_TIMEOUT = 8
HTTP_TIMEOUT = 10
MAX_LATENCY_MS = 3500

def parse_host_port(link: str):
    """Извлекает host и port из vless, trojan или ss ссылки"""
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
    """Первый этап — быстрый TCP тест"""
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

def test_http(link_info: dict):
    """Второй этап — HTTP тест через socks5"""
    try:
        cmd = [
            "timeout", str(HTTP_TIMEOUT),
            "curl", "-x", f"socks5h://{link_info['host']}:{link_info['port']}",
            "-I", "--max-time", "7", "-s", "-o", "/dev/null", "-w", "%{http_code}",
            "https://www.cloudflare.com"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=HTTP_TIMEOUT + 3)
        
        http_code = result.stdout.strip()
        success = http_code in ("200", "301", "302", "403")  # 403 тоже часто проходит у рабочих серверов
        
        if success:
            return link_info["link"]
        return None
    except Exception:
        return None

def main():
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        links = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    print(f"🔍 Запуск комбинированной проверки: TCP + HTTP")
    print(f"Всего ссылок для проверки: {len(links)}\n")

    # Этап 1: TCP проверка
    candidates = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(test_tcp, link): link for link in links}
        for future in as_completed(futures):
            result = future.result()
            if result:
                candidates.append(result)
                print(f"✅ TCP прошёл ({result['latency']} мс) — {result['host']}:{result['port']}")

    print(f"\nПорт открыт у {len(candidates)} ссылок. Запускаем HTTP-тест...\n")

    # Этап 2: HTTP проверка
    working = []
    for i, candidate in enumerate(candidates, 1):
        print(f"[{i}/{len(candidates)}] HTTP-тест: {candidate['host']}:{candidate['port']}")
        result = test_http(candidate)
        if result:
            working.append(result)
            print("   → УСПЕШНО\n")
        else:
            print("   → Не прошёл HTTP-тест\n")
        time.sleep(0.4)  # небольшая пауза

    # Сортируем рабочие ссылки по latency
    working_with_latency = [c for c in candidates if c["link"] in working]
    working_with_latency.sort(key=lambda x: x["latency"])

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for item in working_with_latency:
            f.write(item["link"] + "\n")

    print(f"\n{'='*60}")
    print(f"ФИНАЛЬНЫЙ РЕЗУЛЬТАТ: {len(working)} рабочих ссылок из {len(links)}")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()
