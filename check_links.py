#!/usr/bin/env python3
import sys, os, socket, time, ssl
from urllib.parse import urlparse, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
import base64
import json

# ───────── НАСТРОЙКИ ─────────
INPUT = "mobile-whitelist-1.txt"
OUTPUT = "working_whitelist.txt"
MAX_WORKERS = 20
TEST_TIMEOUT = 2
MAX_LATENCY_MS = 1000
# ─────────────────────────────

def parse_link(link):
    try:
        p = urlparse(link)
        q = parse_qs(p.query)
        h = p.hostname
        port = p.port
        if not h or not port:
            return None, None
        if link.startswith("vless://"):
            uid = p.username or ""
            sec = q.get("security", ["none"])[0]
            cfg = {
                "protocol": "vless",
                "settings": {"vnext": [{"address": h, "port": port, "users": [{"id": uid, "flow": q.get("flow", [""])[0]}]}]},
                "streamSettings": {"network": q.get("type", ["tcp"])[0], "security": sec}
            }
            if sec in ("tls", "reality"):
                cfg["streamSettings"]["tlsSettings"] = {
                    "serverName": q.get("sni", [h])[0],
                    "fingerprint": q.get("fp", ["chrome"])[0],
                    "alpn": q.get("alpn", ["h2,http/1.1"])[0].split(",")
                }
            return cfg, "vless"
        elif link.startswith("trojan://"):
            pwd = unquote(p.username or "")
            return {
                "protocol": "trojan",
                "settings": {"servers": [{"address": h, "port": port, "password": pwd}]},
                "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"serverName": q.get("sni", [h])[0], "alpn": q.get("alpn", ["h2,http/1.1"])[0].split(",")}}
            }, "trojan"
        elif link.startswith("ss://"):
            ui = p.username or ""
            try:
                mp = base64.b64decode(ui).decode() if "@" not in ui else ui.split("@")[0]
            except:
                mp = ui
            pts = mp.split(":", 1)
            return {
                "protocol": "shadowsocks",
                "settings": {"servers": [{"address": h, "port": port, "method": pts[0] if pts else "chacha20-ietf-poly1305", "password": pts[1] if len(pts) > 1 else ""}]}
            }, "shadowsocks"
    except:
        pass
    return None, None

def tcp_check(h, port, timeout):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        t0 = time.time()
        r = s.connect_ex((h, port))
        lat = round((time.time() - t0) * 1000, 1)
        s.close()
        return r == 0, lat
    except:
        return False, None

def tls_check(h, port, timeout):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((h, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=h) as ssock:
                return True
    except:
        return False

def test_proxy(link, port):
    result = {"link": link, "ok": False, "latency": 0, "reason": ""}
    cfg, proto = parse_link(link)
    if not cfg:
        result["reason"] = "parse"
        return result
    try:
        if proto == "vless":
            h = cfg["settings"]["vnext"][0]["address"]
            p = cfg["settings"]["vnext"][0]["port"]
        else:
            h = cfg["settings"]["servers"][0]["address"]
            p = cfg["settings"]["servers"][0]["port"]
    except:
        result["reason"] = "extract"
        return result
    
    ok, lat = tcp_check(h, p, TEST_TIMEOUT)
    if not ok or lat is None:
        result["reason"] = "tcp"
        return result
    
    if lat > MAX_LATENCY_MS:
        result["reason"] = "slow"
        result["latency"] = lat
        return result
    
    result["latency"] = lat
    
    if not tls_check(h, p, TEST_TIMEOUT):
        result["reason"] = "tls"
        return result
    
    result["ok"] = True
    result["reason"] = "ok"
    return result

def convert_to_singbox_outbound(link, index):
    try:
        p = urlparse(link)
        q = parse_qs(p.query)
        h = p.hostname
        port = p.port
        if not h or not port:
            return None

        tag = unquote(p.fragment) if p.fragment else f"Node_{index}_{p.scheme.upper()}"

        if link.startswith("vless://"):
            uid = p.username or ""
            sec = q.get("security", ["none"])[0]
            outbound = {
                "type": "vless",
                "tag": tag,
                "server": h,
                "server_port": int(port),
                "uuid": uid
            }
            if sec in ("tls", "reality"):
                outbound["tls"] = {
                    "enabled": True,
                    "server_name": q.get("sni", [h])[0],
                    "utls": {
                        "enabled": True,
                        "fingerprint": q.get("fp", ["chrome"])[0]
                    }
                }
                if sec == "reality":
                    outbound["tls"]["reality"] = {
                        "enabled": True,
                        "public_key": q.get("pbk", [""])[0],
                        "short_id": q.get("sid", [""])[0]
                    }
            
            net_type = q.get("type", ["tcp"])[0]
            if net_type == "ws":
                outbound["transport"] = {
                    "type": "ws",
                    "path": q.get("path", ["/"])[0],
                    "headers": {"Host": q.get("host", [h])[0]}
                }
            elif net_type == "grpc":
                outbound["transport"] = {
                    "type": "grpc",
                    "service_name": q.get("serviceName", [""])[0]
                }
            return outbound

        elif link.startswith("trojan://"):
            pwd = unquote(p.username or "")
            return {
                "type": "trojan",
                "tag": tag,
                "server": h,
                "server_port": int(port),
                "password": pwd,
                "tls": {
                    "enabled": True,
                    "server_name": q.get("sni", [h])[0]
                }
            }

        elif link.startswith("ss://"):
            ui = p.username or ""
            try:
                mp = base64.b64decode(ui).decode() if "@" not in ui else ui.split("@")[0]
            except:
                mp = ui
            pts = mp.split(":", 1)
            return {
                "type": "shadowsocks",
                "tag": tag,
                "server": h,
                "server_port": int(port),
                "method": pts[0] if pts else "chacha20-ietf-poly1305",
                "password": pts[1] if len(pts) > 1 else ""
            }
    except:
        pass
    return None

def main():
    try:
        if not os.path.exists(INPUT):
            print(f"File {INPUT} not found")
            open(OUTPUT, "w").close()
            return
        with open(INPUT, "r", encoding="utf-8") as f:
            links = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        if not links:
            print("No links")
            open(OUTPUT, "w").close()
            return
        print(f"Checking {len(links)} proxies...")
        working = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futs = {ex.submit(test_proxy, ln, 12000 + i): ln for i, ln in enumerate(links)}
            for fut in as_completed(futs):
                r = fut.result()
                pv = r["link"][:45] + "..." if len(r["link"]) > 45 else r["link"]
                if r["ok"]:
                    working.append(r)
                    print(f"OK ({r['latency']}ms): {pv}")
                else:
                    print(f"FAIL: {pv} | {r['reason']}")
        working.sort(key=lambda x: x["latency"])
        
        with open(OUTPUT, "w", encoding="utf-8") as f:
            for it in working:
                f.write(it["link"] + "\n")
        print(f"\nDone. Working: {len(working)}/{len(links)}")

        if working:
            print("[ИНФО] Сборка умного конфига Sing-box...")
            singbox_outbounds = []
            node_tags = []

            for idx, item in enumerate(working, start=1):
                outbound_obj = convert_to_singbox_outbound(item["link"], idx)
                if outbound_obj:
                    base_tag = outbound_obj["tag"]
                    tag_counter = 1
                    while outbound_obj["tag"] in node_tags:
                        outbound_obj["tag"] = f"{base_tag} ({tag_counter})"
                        tag_counter += 1
                    
                    singbox_outbounds.append(outbound_obj)
                    node_tags.append(outbound_obj["tag"])

            if singbox_outbounds:
                auto_switch_group = {
                    "type": "urltest",
                    "tag": "⚡ Автопереключение",
                    "outbounds": node_tags,
                    "url": "http://www.gstatic.com/generate_204",
                    "interval": "3m",
                    "tolerance": 50
                }

                singbox_config = {
                    "dns": {
                        "servers": [
                            {"tag": "dns_proxy", "address": "https://1.1.1.1/dns-query"},
                            {"tag": "dns_direct", "address": "8.8.8.8", "detour": "direct"}
                        ],
                        "rules": [
                            {"outbound": "any", "server": "dns_proxy"},
                            {"clash_mode": "direct", "server": "dns_direct"}
                        ]
                    },
                    "inbounds": [
                        {
                            "type": "tun",
                            "inet4_address": "172.19.0.1/30",
                            "auto_route": True,
                            "strict_route": True
                        }
                    ],
                    "outbounds": [
                        auto_switch_group,
                        *singbox_outbounds,
                        {"type": "direct", "tag": "direct"},
                        {"type": "block", "tag": "block"}
                    ],
                    "route": {
                        "rules": [{"protocol": "dns", "outbound": "dns_proxy"}],
                        "auto_detect_interface": True
                    }
                }

                with open("singbox_config.json", "w", encoding="utf-8") as sf:
                    json.dump(singbox_config, sf, ensure_ascii=False, indent=2)
                print("[УСПЕХ] Файл конфигурации singbox_config.json успешно сгенерирован!")

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if not os.path.exists(OUTPUT):
            open(OUTPUT, "w").close()
        sys.exit(0)

if __name__ == "__main__":
    main()
