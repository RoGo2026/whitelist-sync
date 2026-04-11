#!/usr/bin/env python3
import socket
import time
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

INPUT_FILE = "mobile-whitelist-1.txt"
OUTPUT_FILE = "working_whitelist.txt"

MAX_WORKERS = 12
TEST_TIMEOUT = 1
MAX_LATENCY_MS = 500
MIN_WORKING_PERCENT = 1

def parse_host_port(link: str):
    try:
        if link.startswith(("vless://", "trojan://")):
            without_scheme = link.split("://", 1)[1]
            at_idx = without_scheme.rfind("@")
            after_at = without_scheme[at_idx + 1:].split("?")[0].split("#")[0]
            if ":" in after_at:
                host, port = after_at.rsplit(":", 1)
                return host.strip("[]"), int(port)
        elif link.startswith("ss://"):
            import base64
            part = link[5:].split("#")[0].split("@")[-1]
            if ":" in part:
                host, port = part.rsplit(":", 1)
                return host.strip("[]"), int(port)
    except Exception:
        pass
    return None, None

def test_link(link: str):
    host, port = parse_host_port(link)
    if not host or not port:
        return None

    start = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TEST_TIMEOUT)
        result = sock.connect_ex((host, port))
        sock.close()
        latency = round((time.time() - start) * 1000, 1)

        if result == 0 and latency <= MAX_LATENCY_MS:
            return {"link": link, "latency": latency}
    except Exception:
        pass
    return None

def main():
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        links = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    print(f"🔍 Проверка {len(links)} ссылок (смягчённый режим)...")

    working = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(test_link, link): link for link in links}
        for future in as_completed(futures):
            result = future.result()
            if result:
                working.append(result)
                print(f"✅ Рабочая ({result['latency']} мс): {result['link'][:60]}...")

    # Сортируем по скорости
    working.sort(key=lambda x: x["latency"])

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for item in working:
            f.write(item["link"] + "\n")

    print(f"\n✅ Проверка завершена. Рабочих ссылок: {len(working)} из {len(links)}")
    if len(working) == 0:
        print("⚠️  Ни одной рабочей ссылки не найдено. Возможно, стоит ещё увеличить таймауты.")

if __name__ == "__main__":
    main()
