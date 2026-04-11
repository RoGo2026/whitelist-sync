#!/usr/bin/env python3
import socket
import time
import sys
import subprocess
import tempfile
import os
import json
import base64
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs
import requests

# -------------------- НАСТРОЙКИ (МЕНЯЙТЕ ЗДЕСЬ) --------------------
INPUT_FILE = "mobile-whitelist-1.txt"
OUTPUT_FILE = "working_whitelist.txt"

MAX_WORKERS_TCP = 15           # Потоков для быстрой TCP-проверки
MAX_WORKERS_HTTP = 3           # Потоков для HTTP-проверки (запуск xray)
TCP_TIMEOUT = 3                # Таймаут TCP подключения (сек)
MAX_LATENCY_MS = 2000          # Максимальная задержка TCP (мс)

HTTP_CHECK_ENABLED = True      # True - TCP + HTTP, False - только TCP
HTTP_TEST_URL = "https://www.youtube.com/"
HTTP_TIMEOUT = 10              # Таймаут HTTP запроса (сек)
XRAY_BIN = "xray"              # Имя бинарника xray (должен быть в PATH)
# -------------------------------------------------------------------

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

def test_link_tcp(link: str):
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
            return {"link": link, "latency": latency}
    except Exception:
        pass
    return None

# ----- Генерация конфига Xray из ссылки (упрощённая, но рабочая) -----
def generate_xray_config(link: str, socks_port: int) -> str:
    if link.startswith("vless://"):
        return _gen_vless_config(link, socks_port)
    elif link.startswith("trojan://"):
        return _gen_trojan_config(link, socks_port)
    elif link.startswith("ss://"):
        return _gen_ss_config(link, socks_port)
    else:
        raise ValueError("Unsupported protocol")

def _gen_vless_config(link: str, socks_port: int) -> str:
    parsed = urlparse(link)
    uuid = parsed.username
    host = parsed.hostname
    port = parsed.port
    query = parse_qs(parsed.query)
    net = query.get("type", ["tcp"])[0]
    security = query.get("security", ["none"])[0]
    sni = query.get("sni", [host])[0]
    path = query.get("path", ["/"])[0]

    config = {
        "inbounds": [{
            "port": socks_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True}
        }],
        "outbounds": [{
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": host,
                    "port": port,
                    "users": [{"id": uuid, "encryption": "none"}]
                }]
            },
            "streamSettings": {
                "network": net,
                "security": security,
                "tlsSettings": {"serverName": sni} if security == "tls" else None,
                "wsSettings": {"path": path} if net == "ws" else None,
                "grpcSettings": {"serviceName": path} if net == "grpc" else None
            }
        }]
    }
    return json.dumps(_remove_none(config))

def _gen_trojan_config(link: str, socks_port: int) -> str:
    parsed = urlparse(link)
    password = parsed.username
    host = parsed.hostname
    port = parsed.port
    query = parse_qs(parsed.query)
    sni = query.get("sni", [host])[0]
    config = {
        "inbounds": [{
            "port": socks_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True}
        }],
        "outbounds": [{
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
                "tlsSettings": {"serverName": sni}
            }
        }]
    }
    return json.dumps(config)

def _gen_ss_config(link: str, socks_port: int) -> str:
    # ss://base64(method:password)@host:port
    if "#" in link:
        link = link.split("#")[0]
    b64_part = link[5:].split("@")[0]
    if "?" in b64_part:
        b64_part = b64_part.split("?")[0]
    decoded = base64.urlsafe_b64decode(b64_part + "==").decode()
    method, password = decoded.split(":", 1)
    host_port = link.split("@")[1].split("?")[0].split("#")[0]
    host, port = host_port.rsplit(":", 1)
    port = int(port)
    config = {
        "inbounds": [{
            "port": socks_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True}
        }],
        "outbounds": [{
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": host,
                    "port": port,
                    "method": method,
                    "password": password
                }]
            }
        }]
    }
    return json.dumps(config)

def _remove_none(obj):
    if isinstance(obj, dict):
        return {k: _remove_none(v) for k, v in obj.items() if v is not None}
    elif isinstance(obj, list):
        return [_remove_none(v) for v in obj if v is not None]
    else:
        return obj

# ----- HTTP проверка с запуском временного xray -----
def test_link_http_with_xray(link: str) -> dict:
    socks_port = random.randint(20000, 30000)
    try:
        config_json = generate_xray_config(link, socks_port)
    except Exception:
        return None

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        f.write(config_json)
        config_path = f.name

    xray_process = None
    try:
        xray_process = subprocess.Popen(
            [XRAY_BIN, "run", "-c", config_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(2)  # Даём время подняться SOCKS

        proxies = {
            "http": f"socks5://127.0.0.1:{socks_port}",
            "https": f"socks5://127.0.0.1:{socks_port}"
        }
        start = time.time()
        resp = requests.get(HTTP_TEST_URL, proxies=proxies, timeout=HTTP_TIMEOUT, stream=True)
        chunk = next(resp.iter_content(1024), None)
        resp.close()
        if resp.status_code == 200 and chunk:
            latency = round((time.time() - start) * 1000, 1)
            return {"link": link, "latency": latency}
    except Exception:
        pass
    finally:
        if xray_process:
            xray_process.terminate()
            try:
                xray_process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                xray_process.kill()
        os.unlink(config_path)
    return None

def main():
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        links = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    print(f"🔍 Проверка {len(links)} ссылок...")

    # TCP фильтрация
    working_tcp = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS_TCP) as executor:
        futures = {executor.submit(test_link_tcp, link): link for link in links}
        for future in as_completed(futures):
            result = future.result()
            if result:
                working_tcp.append(result)
                print(f"✅ TCP OK ({result['latency']} мс): {result['link'][:60]}...")

    print(f"\n📊 После TCP: {len(working_tcp)} рабочих ссылок.")

    if HTTP_CHECK_ENABLED and working_tcp:
        print("🌐 HTTP-проверка через Xray (может занять время)...")
        working_final = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS_HTTP) as executor:
            futures = {executor.submit(test_link_http_with_xray, item["link"]): item for item in working_tcp}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    working_final.append(result)
                    print(f"✅ HTTP OK ({result['latency']} мс): {result['link'][:60]}...")
    else:
        working_final = working_tcp

    working_final.sort(key=lambda x: x["latency"])

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for item in working_final:
            f.write(item["link"] + "\n")

    print(f"\n✅ Проверка завершена. Рабочих ссылок: {len(working_final)} из {len(links)}")

if __name__ == "__main__":
    main()Иллюзия
