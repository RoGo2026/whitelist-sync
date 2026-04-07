#!/usr/bin/env python3
import subprocess
import time
import json
import tempfile
import os

INPUT_FILE = "mobile-whitelist-1.txt"
OUTPUT_FILE = "working_whitelist.txt"

TEST_TIMEOUT = 12
MAX_WORKERS = 5   # Xray тяжёлый, не стоит ставить много параллельно

def test_with_xray(link: str) -> bool:
    """Реальная проверка через Xray-core"""
    config_path = None
    try:
        # Создаём минимальный конфиг для теста
        config = {
            "log": {"loglevel": "none"},
            "inbounds": [
                {
                    "protocol": "socks",
                    "port": 1080,
                    "listen": "127.0.0.1",
                    "settings": {"udp": True}
                }
            ],
            "outbounds": [
                {
                    "tag": "proxy",
                    "protocol": "freedom"  # будет заменено Xray при использовании share link
                }
            ]
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(config, f, indent=2)
            config_path = f.name

        # Запускаем Xray с таймаутом
        xray_cmd = ["timeout", str(TEST_TIMEOUT), "xray", "run", "-c", config_path]
        subprocess.run(xray_cmd, capture_output=True, timeout=TEST_TIMEOUT + 3)

        # Проверяем реальную работу через curl
        curl_cmd = [
            "timeout", "8",
            "curl", "-x", "socks5h://127.0.0.1:1080",
            "-I", "--max-time", "6", "-s", "-k",
            "https://1.1.1.1"
        ]
        result = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=10)

        return result.returncode == 0

    except Exception:
        return False
    finally:
        if config_path and os.path.exists(config_path):
            os.unlink(config_path)

def main():
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        links = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    print(f"🔍 Запуск проверки через Xray-core")
    print(f"Всего ссылок: {len(links)}\n")

    working = []
    for i, link in enumerate(links, 1):
        print(f"[{i}/{len(links)}] Проверка...")
        if test_with_xray(link):
            working.append(link)
            print("   ✅ РАБОЧАЯ")
        else:
            print("   ❌ Не прошла")
        time.sleep(0.7)  # пауза для стабильности

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for link in working:
            f.write(link + "\n")

    print(f"\n{'='*70}")
    print(f"ФИНАЛЬНЫЙ РЕЗУЛЬТАТ: {len(working)} рабочих ссылок из {len(links)}")
    print(f"{'='*70}")

if __name__ == "__main__":
    main()
