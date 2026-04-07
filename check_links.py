#!/usr/bin/env python3
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

INPUT_FILE = "mobile-whitelist-1.txt"
OUTPUT_FILE = "working_whitelist.txt"

# ==================== НАСТРОЙКИ ====================
MAX_WORKERS = 6
HTTP_TIMEOUT = 5          # жёстко
MAX_HTTP_ATTEMPTS = 1     # только одна попытка
TEST_URL = "https://1.1.1.1"
# ===================================================

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

def test_link(link: str) -> bool:
    info = parse_host_port(link)
    if not info:
        return False
    host, port = info

    try:
        cmd = [
            "timeout", "7",                     # жёсткий внешний таймаут
            "curl", 
            "-x", f"socks5h://{host}:{port}",
            "-I", "--max-time", str(HTTP_TIMEOUT),
            "-s", "-k", "-o", "/dev/null",
            "-w", "%{http_code}", 
            TEST_URL
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
        http_code = result.stdout.strip()
        return http_code in ("200", "301", "302", "403", "000")
    except Exception:
        return False

def main():
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        links = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    print(f"🔍 Быстрая проверка (timeout = {HTTP_TIMEOUT} сек, 1 попытка)")
    print(f"Всего ссылок: {len(links)}\n")

    working = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(test_link, link): link for link in links}
        for future in as_completed(futures):
            link = futures[future]
            if future.result():
                working.append(link)
                print(f"✅")
            else:
                print(f"❌")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for link in working:
            f.write(link + "\n")

    print(f"\n{'='*60}")
    print(f"ГОТОВО: {len(working)} рабочих из {len(links)}")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()
