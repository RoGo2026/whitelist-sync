#!/usr/bin/env python3
import json
import subprocess
import tempfile
import os
import time
from pathlib import Path

INPUT_FILE = "mobile-whitelist-1.txt"
OUTPUT_FILE = "working_whitelist.txt"

TEST_TIMEOUT = 15      # секунд на один тест
MAX_LATENCY = 3000     # мс

def test_with_xray(link: str) -> bool:
    """Проверка одной ссылки через реальный Xray-core"""
    try:
        # Создаём минимальный конфиг для теста
        config = {
            "log": {"loglevel": "error"},
            "inbounds": [
                {
                    "protocol": "dokodemo-door",
                    "port": 1080,
                    "listen": "127.0.0.1",
                    "settings": {"network": "tcp,udp"}
                }
            ],
            "outbounds": [
                {
                    "tag": "proxy",
                    "protocol": "vless" if link.startswith("vless://") else "trojan" if link.startswith("trojan://") else "shadowsocks",
                    "settings": {}  # Xray сам разберёт share link при запуске с -format=uri в новых версиях
                }
            ]
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(config, f, indent=2)
            cfg_path = f.name

        # Запускаем Xray с таймаутом
        cmd = ["timeout", str(TEST_TIMEOUT), "xray", "run", "-c", cfg_path]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=TEST_TIMEOUT + 5)

        # Дополнительный тест — пытаемся сделать запрос через прокси
        curl_cmd = [
            "timeout", "8", "curl", "-x", "socks5h://127.0.0.1:1080",
            "-I", "--max-time", "6", "-s", "https://www.google.com"
        ]
        curl_result = subprocess.run(curl_cmd, capture_output=True, text=True)

        success = curl_result.returncode == 0 and ("HTTP/1" in curl_result.stdout or "HTTP/2" in curl_result.stdout)

        return success

    except Exception as e:
        return False
    finally:
        try:
            os.unlink(cfg_path)
        except:
            pass

def main():
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        links = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    print(f"🔍 Начинаем реальную проверку {len(links)} ссылок через Xray-core...")

    working = []
    for i, link in enumerate(links, 1):
        print(f"[{i}/{len(links)}] Проверка...")
        if test_with_xray(link):
            working.append(link)
            print("✅ Прошла реальную проверку")
        else:
            print("❌ Не прошла")

        time.sleep(0.5)  # небольшая пауза, чтобы не перегружать runner

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for link in working:
            f.write(link + "\n")

    print(f"\n✅ Проверка завершена. Рабочих ссылок: {len(working)} из {len(links)}")

if __name__ == "__main__":
    main()
