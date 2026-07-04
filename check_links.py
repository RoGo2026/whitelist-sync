#!/usr/bin/env python3
import sys, os, socket, time, ssl, json
from urllib.parse import urlparse, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
import base64

# ───────── НАСТРОЙКИ ─────────
INPUT = "mobile-whitelist-1.txt"
OUTPUT = "singbox.json"
MAX_WORKERS = 20
TEST_TIMEOUT = 2
MAX_LATENCY_MS = 1000
# ─────────────────────────────

def parse_link_to_singbox(link, index):
    """Парсит ссылку и возвращает конфигурацию в формате Sing-box"""
    try:
        p = urlparse(link)
        q = parse_qs(p.query)
        h = p.hostname
        port = p.port
        
        if not h or not port:
            return None, None, None, None
        
        tag = f"Server_{index+1}"
        
        if link.startswith("vless://"):
            uid = p.username or ""
            sec = q.get("security", ["none"])[0]
            flow = q.get("flow", [""])[0]
            network = q.get("type", ["tcp"])[0]
            sni = q.get("sni", [h])[0]
            fp = q.get("fp", ["chrome"])[0]
            alpn = q.get("alpn", ["h2,http/1.1"])[0].split(",")
            
            cfg = {
                "type": "vless",
                "tag": tag,
                "server": h,
                "server_port": port,
                "uuid": uid,
                "flow": flow if flow else None
            }
            
            if sec in ("tls", "reality"):
                cfg["tls"] = {
                    "enabled": True,
                    "server_name": sni,
                    "alpn": alpn
                }
                
                if sec == "reality":
                    cfg["tls"]["reality"] = {
                        "enabled": True,
                        "public_key": q.get("pbk", [""])[0],
                        "short_id": q.get("sid", [""])[0]
                    }
                    if fp:
                        cfg["tls"]["utls"] = {
                            "enabled": True,
                            "fingerprint": fp
                        }
                else:
                    if fp:
                        cfg["tls"]["utls"] = {
                            "enabled": True,
                            "fingerprint": fp
                        }
            
            if network != "tcp":
                cfg["transport"] = {"type": network}
                if network == "ws":
                    cfg["transport"]["path"] = q.get("path", ["/"])[0]
                    cfg["transport"]["headers"] = {"Host": q.get("host", [h])[0]}
            
            return cfg, "vless", h, port
            
        elif link.startswith("trojan://"):
            pwd = unquote(p.username or "")
            sni = q.get("sni", [h])[0]
            alpn = q.get("alpn", ["h2,http/1.1"])[0].split(",")
            
            cfg = {
                "type": "trojan",
                "tag": tag,
                "server": h,
                "server_port": port,
                "password": pwd,
                "tls": {
                    "enabled": True,
                    "server_name": sni,
                    "alpn": alpn
                }
            }
            
            return cfg, "trojan", h, port
            
        elif link.startswith("ss://"):
            ui = p.username or ""
            try:
                mp = base64.b64decode(ui).decode() if "@" not in ui else ui.split("@")[0]
            except:
                mp = ui
            pts = mp.split(":", 1)
            method = pts[0] if pts else "chacha20-ietf-poly1305"
            password = pts[1] if len(pts) > 1 else ""
            
            cfg = {
                "type": "shadowsocks",
                "tag": tag,
                "server": h,
                "server_port": port,
                "method": method,
                "password": password
            }
            
            return cfg, "shadowsocks", h, port
            
    except Exception as e:
        print(f"Parse error: {e}")
        pass
    
    return None, None, None, None

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

def test_proxy(link, index):
    result = {"link": link, "ok": False, "latency": 0, "reason": "", "cfg": None, "tag": None}
    
    cfg, proto, h, port = parse_link_to_singbox(link, index)
    if not cfg:
        result["reason"] = "parse"
        return result
    
    result["cfg"] = cfg
    result["tag"] = cfg["tag"]
    
    ok, lat = tcp_check(h, port, TEST_TIMEOUT)
    if not ok or lat is None:
        result["reason"] = "tcp"
        return result
    
    if lat > MAX_LATENCY_MS:
        result["reason"] = "slow"
        result["latency"] = lat
        return result
    
    result["latency"] = lat
    
    if not tls_check(h, port, TEST_TIMEOUT):
        result["reason"] = "tls"
        return result
    
    result["ok"] = True
    result["reason"] = "ok"
    return result

def main():
    try:
        if not os.path.exists(INPUT):
            print(f"File {INPUT} not found")
            json_cfg = {"outbounds": []}
            with open(OUTPUT, "w", encoding="utf-8") as f:
                json.dump(json_cfg, f, indent=2, ensure_ascii=False)
            return
        
        with open(INPUT, "r", encoding="utf-8") as f:
            links = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        
        if not links:
            print("No links")
            json_cfg = {"outbounds": []}
            with open(OUTPUT, "w", encoding="utf-8") as f:
                json.dump(json_cfg, f, indent=2, ensure_ascii=False)
            return
        
        print(f"Checking {len(links)} proxies...")
        print(f"Settings: workers={MAX_WORKERS}, timeout={TEST_TIMEOUT}s, max_latency={MAX_LATENCY_MS}ms")
        
        working = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futs = {ex.submit(test_proxy, ln, i): ln for i, ln in enumerate(links)}
            for fut in as_completed(futs):
                r = fut.result()
                pv = r["link"][:45] + "..." if len(r["link"]) > 45 else r["link"]
                if r["ok"]:
                    working.append(r)
                    print(f"OK ({r['latency']}ms): {pv}")
                else:
                    print(f"FAIL: {pv} | {r['reason']}")
        
        working.sort(key=lambda x: x["latency"])
        
        outbounds = []
        server_tags = []
        
        for item in working:
            cfg = item["cfg"]
            cfg = {k: v for k, v in cfg.items() if v is not None}
            outbounds.append(cfg)
            server_tags.append(cfg["tag"])
        
        if server_tags:
            urltest_group = {
                "type": "urltest",
                "tag": "Автопереключение",
                "outbounds": server_tags,
                "interval": "1m",
                "tolerance": 50
            }
            outbounds.insert(0, urltest_group)
            
            selector_group = {
                "type": "selector",
                "tag": "Ручной выбор",
                "outbounds": server_tags
            }
            outbounds.insert(1, selector_group)
        
        json_cfg = {
            "outbounds": outbounds
        }
        
        with open(OUTPUT, "w", encoding="utf-8") as f:
            json.dump(json_cfg, f, indent=2, ensure_ascii=False)
        
        print(f"\nDone. Working: {len(working)}/{len(links)}")
        print(f"JSON saved to {OUTPUT}")
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if not os.path.exists(OUTPUT):
            json_cfg = {"outbounds": []}
            with open(OUTPUT, "w", encoding="utf-8") as f:
                json.dump(json_cfg, f, indent=2, ensure_ascii=False)
        sys.exit(0)

if __name__ == "__main__":
    main()
