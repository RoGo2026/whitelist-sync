#!/usr/bin/env python3
# check_proxies_advanced.py
# Проверка vless:// trojan:// ss:// ссылок с реальным HTTP-тестом
# Требует: установленный xray-core или sing-box в системе (или в PATH)

import socket
import time
import sys
import os
import subprocess
import json
import random
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, unquote
import base64

# ================= НАСТРОЙКИ =================
INPUT_FILE = "mobile-whitelist-1.txt"
OUTPUT_FILE = "working_whitelist.txt"
RESULTS_FILE = "proxy_test_results.json"

MAX_WORKERS = 8  # Уменьшено: запуск локального прокси ресурсоёмкий
TCP_TIMEOUT = 2.0
HTTP_TEST_TIMEOUT = 8.0
MAX_LATENCY_MS = 500
TEST_URL = "https://www.google.com/generate_204"  # Возвращает 204, быстро, без контента
LOCAL_SOCKS_PORT_START = 10000  # Порт для локального SOCKS5-туннеля
XRAY_PATH = "xray"  # Или полный путь, например "/usr/local/bin/xray"
SINGBOX_PATH = "sing-box"  # Альтернатива
# =============================================

def parse_vless(link: str) -> dict:
    """Парсит vless:// ссылку, возвращает конфиг для xray"""
    try:
        parsed = urlparse(link)
        query = parse_qs(parsed.query)
        user_id = parsed.username or ""
        host, port = parsed.hostname, parsed.port
        flow = query.get("flow", [""])[0]
        security = query.get("security", ["none"])[0]
        sni = query.get("sni", [host])[0]
        fp = query.get("fp", ["chrome"])[0]
        alpn = query.get("alpn", ["h2,http/1.1"])[0]
        pbk = query.get("pbk", [""])[0]
        sid = query.get("sid", [""])[0]
        
        config = {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": host,
                    "port": port,
                    "users": [{"id": user_id, "flow": flow}]
                }]
            },
            "streamSettings": {
                "network": query.get("type", ["tcp"])[0],
                "security": security,
                "tlsSettings": {
                    "serverName": sni,
                    "fingerprint": fp,
                    "alpn": alpn.split(","),
                    "publicKey": pbk,
                    "shortId": sid
                } if security in ("tls", "reality") else {}
            }
        }
        return config
    except Exception as e:
        print(f"⚠️  Ошибка парсинга vless: {e}")
        return None

def parse_trojan(link: str) -> dict:
    """Парсит trojan:// ссылку"""
    try:
        parsed = urlparse(link)
        query = parse_qs(parsed.query)
        password = unquote(parsed.username or "")
        host, port = parsed.hostname, parsed.port
        sni = query.get("sni", [host])[0]
        alpn = query.get("alpn", ["h2,http/1.1"])[0]
        
        config = {
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": host,
                    "port": port,
                    "password": password
                }]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "serverName": sni,
                    "alpn": alpn.split(",")
                }
            }
        }
        return config
    except Exception as e:
        print(f"⚠️  Ошибка парсинга trojan: {e}")
        return None

def parse_ss(link: str) -> dict:
    """Парсит ss:// ссылку"""
    try:
        parsed = urlparse(link)
        host, port = parsed.hostname, parsed.port
        # Декодируем user:pass@host:port или base64(method:pass)@host:port
        userinfo = parsed.username or ""
        if "@" in userinfo:
            method_pass, _ = userinfo.split("@", 1)
        else:
            # Попробуем декодировать base64
            try:
                decoded = base64.b64decode(userinfo).decode().split(":")
                method_pass = decoded[0] + ":" + decoded[1] if len(decoded) > 1 else decoded[0]
            except:
                method_pass = userinfo
        
        parts = method_pass.split(":")
        if len(parts) >= 2:
            method, password = parts[0], ":".join(parts[1:])
        else:
            method, password = "chacha20-ietf-poly1305", parts[0]
        
        return {
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": host,
                    "port": port,
                    "method": method,
                    "password": password
                }]
            }
        }
    except Exception as e:
        print(f"⚠️  Ошибка парсинга ss: {e}")
        return None

def parse_link(link: str) -> tuple:
    """Возвращает (config_dict, protocol_name) или (None, None)"""
    if link.startswith("vless://"):
        return parse_vless(link), "vless"
    elif link.startswith("trojan://"):
        return parse_trojan(link), "trojan"
    elif link.startswith("ss://"):
        return parse_ss(link), "shadowsocks"
    return None, None

def tcp_check(host: str, port: int, timeout: float) -> tuple:
    """TCP проверка: (успех, задержка_мс)"""
    start = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        latency = round((time.time() - start) * 1000, 1)
        return (result == 0, latency)
    except:
        return (False, None)

def start_local_socks_proxy(config: dict, protocol: str, local_port: int, core="xray") -> subprocess.Popen:
    """Запускает локальный SOCKS5-прокси через xray/sing-box"""
    # Генерируем временный конфиг
    xray_config = {
        "log": {"loglevel": "error"},
        "inbounds": [{
            "port": local_port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False}
        }],
        "outbounds": [{
            "protocol": protocol,
            "settings": config["settings"],
            "streamSettings": config.get("streamSettings")
        }]
    }
    
    config_file = f"/tmp/xray_config_{local_port}.json"
    with open(config_file, "w") as f:
        json.dump(xray_config, f)
    
    cmd = [XRAY_PATH if core == "xray" else SINGBOX_PATH, "run", "-config", config_file]
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True
        )
        time.sleep(1.5)  # Ждём запуска
        return proc
    except Exception as e:
        print(f"❌ Не удалось запустить {core}: {e}")
        return None

def test_through_socks(socks_port: int, timeout: float) -> bool:
    """Делает реальный HTTP-запрос через локальный SOCKS5"""
    try:
        import requests
        from requests.exceptions import ProxyError, ConnectTimeout, ReadTimeout
        
        proxies = {
            "http": f"socks5://127.0.0.1:{socks_port}",
            "https": f"socks5://127.0.0.1:{socks_port}"
        }
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "*/*"
        }
        
        resp = requests.get(
            TEST_URL,
            proxies=proxies,
            headers=headers,
            timeout=timeout,
            verify=True,
            allow_redirects=False
        )
        # 204 = успех, 301/302 = редирект (тоже ок), 429 = лимит (прокси работает)
        return resp.status_code in (204, 301, 302, 429)
    except (ProxyError, ConnectTimeout, ReadTimeout):
        return False
    except Exception:
        return False

def test_link(link: str, local_port: int) -> dict:
    """Полная проверка одной ссылки"""
    result = {"link": link, "status": "dead", "latency": None, "reason": ""}
    
    config, protocol = parse_link(link)
    if not config:
        result["reason"] = "parse_failed"
        return result
    
    # Извлекаем host:port для TCP-проверки
    if protocol == "vless":
        host = config["settings"]["vnext"][0]["address"]
        port = config["settings"]["vnext"][0]["port"]
    elif protocol == "trojan":
        host = config["settings"]["servers"][0]["address"]
        port = config["settings"]["servers"][0]["port"]
    else:  # shadowsocks
        host = config["settings"]["servers"][0]["address"]
        port = config["settings"]["servers"][0]["port"]
    
    # 1. TCP проверка
    tcp_ok, tcp_latency = tcp_check(host, port, TCP_TIMEOUT)
    if not tcp_ok or tcp_latency is None or tcp_latency > MAX_LATENCY_MS:
        result["reason"] = "tcp_failed_or_slow"
        return result
    result["latency"] = tcp_latency
    
    # 2. Запускаем локальный SOCKS5-туннель
    proc = start_local_socks_proxy(config, protocol, local_port)
    if not proc:
        result["reason"] = "core_start_failed"
        return result
    
    try:
        # 3. Реальный HTTP-тест через туннель
        if test_through_socks(local_port, HTTP_TEST_TIMEOUT):
            result["status"] = "ok"
            result["reason"] = "http_test_passed"
        else:
            result["reason"] = "http_test_failed"
    finally:
        # 4. Убиваем локальный прокси
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except:
            os.kill(proc.pid, signal.SIGKILL)
        # Чистим конфиг
        try:
            os.remove(f"/tmp/xray_config_{local_port}.json")
        except:
            pass
    
    return result

def main():
    # Проверка зависимостей
    if not any(os.path.exists(p) for p in [XRAY_PATH, SINGBOX_PATH]):
        print(f"❌ Ошибка: не найден {XRAY_PATH} или {SINGBOX_PATH}")
        print("💡 Установите xray-core: https://github.com/XTLS/Xray-core/releases")
        print("   Или sing-box: https://github.com/SagerNet/sing-box/releases")
        print("   И добавьте в PATH или укажите полный путь в настройках скрипта")
        sys.exit(1)
    
    try:
        with open(INPUT_FILE, "r", encoding="utf-8") as f:
            links = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
    except FileNotFoundError:
        print(f"❌ Ошибка: файл {INPUT_FILE} не найден")
        sys.exit(1)
    
    if not links:
        print("❌ Список ссылок пуст")
        sys.exit(1)
    
    print(f"🔍 Проверка {len(links)} ссылок (TCP + реальный HTTP-тест через туннель)...")
    print(f"📦 Используется: {XRAY_PATH if os.path.exists(XRAY_PATH) else SINGBOX_PATH}")
    
    working = []
    results = []
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Генерируем уникальные порты для каждого воркера
        futures = {}
        for i, link in enumerate(links):
            port = LOCAL_SOCKS_PORT_START + i
            futures[executor.submit(test_link, link, port)] = link
        
        for future in as_completed(futures):
            res = future.result()
            results.append(res)
            
            if res["status"] == "ok":
                working.append(res)
                preview = res['link'][:50] + "..." if len(res['link']) > 50 else res['link']
                print(f"✅ Рабочая ({res['latency']} мс): {preview}")
            else:
                preview = res['link'][:50] + "..." if len(res['link']) > 50 else res['link']
                print(f"❌ {preview} | {res['reason']}")
    
    # Сортируем по скорости
    working.sort(key=lambda x: x["latency"])
    
    # Сохраняем результаты
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for item in working:
            f.write(item["link"] + "\n")
    
    with open(RESULTS_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"\n✅ Проверка завершена. Рабочих: {len(working)} из {len(links)}")
    print(f"💾 Рабочие: {OUTPUT_FILE}")
    print(f"📄 Отчёт: {RESULTS_FILE}")
    
    if len(working) == 0:
        print("⚠️  Ни одной рабочей ссылки. Проверь: 1) установлен ли xray/sing-box, 2) таймауты, 3) сеть на раннере")

if __name__ == "__main__":
    main()
