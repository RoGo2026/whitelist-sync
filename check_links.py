#!/usr/bin/env python3
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

INPUT_FILE = "mobile-whitelist-1.txt"
OUTPUT_FILE = "working_whitelist.txt"

# ==================== МАКСИМАЛЬНО ЖЁСТКИЕ НАСТРОЙКИ ====================
MAX_WORKERS = 7
TCP_TIMEOUT = 2
MAX_LATENCY_MS = 1500 
# =====================================================================

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
            part = link[5:].split("#")[0].split("@")[-1]
            if ":" in part:
                host, port = part.rsplit(":", 1)
                return host.strip("[]"), int(port)
    except Exception:
        pass
    return None, None

def test_link(link: str):
    info = parse_host_port(link)
    if not info:
        return None
    host, port = info

    start = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TCP_TIMEOUT)
        result = sock.connect_ex((host, port))
        sock.close()
        latency = round((time.time() - start) * 1000, 1)

        # Очень жёсткое условие
        if result == 0 and latency <= MAX_LATENCY_MS:
            return {"link": link, "latency": latency}
    except Exception:
        pass
    return None

def main():
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        links = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    print(f"🔍 МАКСИМАЛЬНО ЖЁСТКАЯ TCP-проверка")
    print(f"TCP_TIMEOUT = {TCP_TIMEOUT} сек | MAX_LATENCY_MS = {MAX_LATENCY_MS} мс")
    print(f"Всего ссылок: {len(links)}\n")

    working = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(test_link, link): link for link in links}
        for future in as_completed(futures):
            result = future.result()
            if result:
                working.append(result)
                print(f"✅ {result['latency']} мс")
            else:
                print("❌")

    working.sort(key=lambda x: x["latency"])

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for item in working:
            f.write(item["link"] + "\n")

    print(f"\n{'='*75}")
    print(f"МАКСИМАЛЬНО ЖЁСТКИЙ ОТБОР: {len(working)} рабочих ссылок из {len(links)}")
    print(f"{'='*75}")

if __name__ == "__main__":
    main()
