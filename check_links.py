#!/usr/bin/env python3
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

INPUT_FILE = "mobile-whitelist-1.txt"
OUTPUT_FILE = "working_whitelist.txt"

# ==================== НАСТРОЙКИ ====================
MAX_WORKERS = 2
HTTP_TIMEOUT = 2
MAX_HTTP_ATTEMPTS = 2
TEST_URL = "https://1.1.1.1"
# ===================================================

def test_link(link: str) -> bool:
    """Только HTTP-проверка через 1.1.1.1"""
    for attempt in range(1, MAX_HTTP_ATTEMPTS + 1):
        try:
            cmd = [
                "timeout", str(HTTP_TIMEOUT + 4),
                "curl", 
                "-x", f"socks5h://{link}",      # Прямая ссылка
                "-I", 
                "--max-time", str(HTTP_TIMEOUT),
                "-s", "-k", "-o", "/dev/null",
                "-w", "%{http_code}", 
                TEST_URL
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=HTTP_TIMEOUT + 6)
            
            http_code = result.stdout.strip()
            
            # Успешные коды
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

    print(f"🔍 Проверка ТОЛЬКО через HTTP → {TEST_URL}")
    print(f"Всего ссылок: {len(links)}\n")

    working = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(test_link, link): link for link in links}
        
        for future in as_completed(futures):
            link = futures[future]
            if future.result():
                working.append(link)
                print(f"✅ РАБОЧАЯ")
            else:
                print(f"❌ Не прошла")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for link in working:
            f.write(link + "\n")

    print(f"\n{'='*70}")
    print(f"ФИНАЛЬНЫЙ РЕЗУЛЬТАТ: {len(working)} рабочих ссылок из {len(links)}")
    print(f"{'='*70}")

if __name__ == "__main__":
    main()
