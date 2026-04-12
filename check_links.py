#!/usr/bin/env python3
import socket
import ssl
import time
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# ================= НАСТРОЙКИ =================
INPUT_FILE = "mobile-whitelist-1.txt"
OUTPUT_FILE = "working_whitelist.txt"

MAX_WORKERS = 12
TEST_TIMEOUT = 2.5          # Увеличено для прохождения TLS-рукопожатия
MAX_LATENCY_MS = 500
MIN_WORKING_PERCENT = 1
# =============================================

def parse_host_port(link: str):
    """Извлекает host:port из vless:// trojan:// ss:// ссылок"""
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

def tcp_check(host: str, port: int, timeout: float) -> tuple:
    """TCP проверка: возвращает (успех, задержка_мс)"""
    start = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        latency = round((time.time() - start) * 1000, 1)
        return (result == 0, latency)
    except Exception:
        return (False, None)

def https_handshake_test(host: str, port: int, timeout: float) -> bool:
    """
    Проверяет, может ли хост завершить TLS handshake.
    Это отсеивает прокси, которые принимают TCP, но ломают HTTPS (YouTube не грузится).
    """
    try:
        context = ssl.create_default_context()
        # Не проверяем сертификат и хостнейм — нам важна только возможность рукопожатия
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # Если код дошёл сюда — рукопожатие успешно, прокси умеет в HTTPS
                return True
    except (ssl.SSLError, socket.timeout, OSError, ConnectionResetError):
        return False
    except Exception:
        return False

def test_link(link: str):
    host, port = parse_host_port(link)
    if not host or not port:
        return None

    # === ЭТАП 1: Быстрая TCP проверка ===
    tcp_ok, tcp_latency = tcp_check(host, port, TEST_TIMEOUT)
    if not tcp_ok or tcp_latency is None or tcp_latency > MAX_LATENCY_MS:
        return None

    # === ЭТАП 2: Проверка HTTPS/TLS (ключевой фильтр для YouTube) ===
    # Если прокси не может завершить TLS-рукопожатие, YouTube через него не заработает
    if not https_handshake_test(host, port, TEST_TIMEOUT):
        return None

    # Обе проверки пройдены — прокси годный
    return {"link": link, "latency": tcp_latency}

def main():
    try:
        with open(INPUT_FILE, "r", encoding="utf-8") as f:
            links = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
    except FileNotFoundError:
        print(f"❌ Ошибка: файл {INPUT_FILE} не найден")
        sys.exit(1)

    if not links:
        print("❌ Список ссылок пуст")
        sys.exit(1)

    print(f"🔍 Проверка {len(links)} ссылок (TCP + TLS handshake)...")

    working = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(test_link, link): link for link in links}
        for future in as_completed(futures):
            result = future.result()
            if result:
                working.append(result)
                preview = result['link'][:60] + "..." if len(result['link']) > 60 else result['link']
                print(f"✅ Рабочая ({result['latency']} мс): {preview}")

    # Сортируем по скорости
    working.sort(key=lambda x: x["latency"])

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for item in working:
            f.write(item["link"] + "\n")

    print(f"\n✅ Проверка завершена. Рабочих ссылок: {len(working)} из {len(links)}")
    if len(working) == 0:
        print("⚠️  Ни одной рабочей ссылки не найдено.")

if __name__ == "__main__":
    main()
