#!/usr/bin/env python3
import socket
import time
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

# -------------------- НАСТРОЙКИ (МЕНЯЙТЕ ЗДЕСЬ) --------------------
INPUT_FILE = "mobile-whitelist-1.txt"
OUTPUT_FILE = "working_whitelist.txt"

MAX_WORKERS = 15               # Сколько ссылок проверять одновременно
TEST_TIMEOUT = 3               # Таймаут TCP подключения (сек)
MAX_LATENCY_MS = 2000          # Максимальная задержка TCP (мс)

# HTTP проверка (через уже запущенный локальный прокси)
HTTP_CHECK_ENABLED = True      # True - включить, False - только TCP
LOCAL_PROXY = "socks5://127.0.0.1:1080"   # Адрес вашего SOCKS5 прокси
HTTP_TEST_URL = "https://www.github.com/"
HTTP_TIMEOUT = 10              # Таймаут HTTP запроса (сек)
# ----------------------------------------------------------------

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

def test_link_tcp(link: str):
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

def test_link_http(link: str):
    """Проверяет доступность HTTP через локальный прокси (SOCKS5)."""
    try:
        proxies = {
            "http": LOCAL_PROXY,
            "https": LOCAL_PROXY
        }
        start = time.time()
        resp = requests.get(HTTP_TEST_URL, proxies=proxies, timeout=HTTP_TIMEOUT, stream=True)
        # Читаем немного данных для проверки реальной загрузки
        chunk = next(resp.iter_content(1024), None)
        resp.close()
        if resp.status_code == 200 and chunk:
            latency = round((time.time() - start) * 1000, 1)
            return {"link": link, "latency": latency}
    except Exception:
        pass
    return None

def main():
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        links = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    print(f"🔍 Проверка {len(links)} ссылок...")
    if HTTP_CHECK_ENABLED:
        print(f"🌐 HTTP-проверка включена (прокси: {LOCAL_PROXY}, URL: {HTTP_TEST_URL})")

    working_tcp = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(test_link_tcp, link): link for link in links}
        for future in as_completed(futures):
            result = future.result()
            if result:
                working_tcp.append(result)
                print(f"✅ TCP OK ({result['latency']} мс): {result['link'][:60]}...")

    print(f"\n📊 После TCP: {len(working_tcp)} рабочих ссылок.")

    if HTTP_CHECK_ENABLED:
        working_final = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(test_link_http, item["link"]): item for item in working_tcp}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    working_final.append(result)
                    print(f"✅ HTTP OK ({result['latency']} мс): {result['link'][:60]}...")
    else:
        working_final = working_tcp

    # Сортировка по задержке
    working_final.sort(key=lambda x: x["latency"])

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for item in working_final:
            f.write(item["link"] + "\n")

    print(f"\n✅ Проверка завершена. Рабочих ссылок: {len(working_final)} из {len(links)}")
    if len(working_final) == 0:
        print("⚠️  Ни одной рабочей ссылки не найдено.")

if __name__ == "__main__":
    main()
