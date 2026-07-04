#!/usr/bin/env python3
import sys, os, socket, time
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

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
        h = p.hostname
        port = p.port
        if not h or not port:
            return None, None
        if link.startswith("vless://") or link.startswith("trojan://") or link.startswith("ss://"):
            return {"host": h, "port": port}, p.scheme
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

def test_proxy(link):
    result = {"link": link, "ok": False, "latency": 0, "reason": ""}
    cfg, proto = parse_link(link)
    if not cfg:
        result["reason"] = "parse error"
        return result
    
    ok, lat = tcp_check(cfg["host"], cfg["port"], TEST_TIMEOUT)
    if not ok or lat is None:
        result["reason"] = "tcp fail"
        return result
    
    if lat > MAX_LATENCY_MS:
        result["reason"] = f"slow ({lat}ms)"
        result["latency"] = lat
        return result
    
    result["latency"] = lat
    result["ok"] = True
    result["reason"] = "ok"
    return result

def main():
    try:
        if not os.path.exists(INPUT):
            print(f"File {INPUT} not found")
            open(OUTPUT, "w").close()
            return
            
        with open(INPUT, "r", encoding="utf-8") as f:
            links = [l.strip() for l in f if l.strip() and not l.startswith("#")]
            
        if not links:
            print("No links found")
            open(OUTPUT, "w").close()
            return
            
        print(f"Checking {len(links)} proxies...")
        working = []
        
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futs = {ex.submit(test_proxy, ln): ln for ln in links}
            for fut in as_completed(futs):
                r = fut.result()
                pv = r["link"][:45] + "..." if len(r["link"]) > 45 else r["link"]
                if r["ok"]:
                    working.append(r)
                    print(f"OK ({r['latency']}ms): {pv}")
                else:
                    print(f"FAIL: {pv} | {r['reason']}")
                    
        # Сортируем так, чтобы самые быстрые были на самом верху списка
        working.sort(key=lambda x: x["latency"])
        
        with open(OUTPUT, "w", encoding="utf-8") as f:
            for it in working:
                f.write(it["link"] + "\n")
                
        print(f"\nDone. Working: {len(working)}/{len(links)}")

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
