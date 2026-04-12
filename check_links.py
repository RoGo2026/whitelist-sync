#!/usr/bin/env python3
import sys, os, socket, time
from urllib.parse import urlparse

INPUT = "mobile-whitelist-1.txt"
OUTPUT = "working_whitelist.txt"

def check_proxy(link):
    try:
        p = urlparse(link)
        host = p.hostname
        port = p.port
        if not host or not port:
            return False, 0
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.5)
        start = time.time()
        result = sock.connect_ex((host, port))
        latency = round((time.time() - start) * 1000, 1)
        sock.close()
        if result == 0 and latency < 1000:
            return True, latency
        return False, latency
    except:
        return False, 0

def main():
    try:
        if not os.path.exists(INPUT):
            print(f"File {INPUT} not found")
            open(OUTPUT, "w").close()
            return
        with open(INPUT, "r", encoding="utf-8") as f:
            links = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        if not links:
            print("No links found")
            open(OUTPUT, "w").close()
            return
        print(f"Checking {len(links)} proxies...")
        working = []
        for i, link in enumerate(links):
            ok, lat = check_proxy(link)
            preview = link[:50] + "..." if len(link) > 50 else link
            if ok:
                working.append((link, lat))
                print(f"OK ({lat}ms): {preview}")
            else:
                print(f"FAIL: {preview}")
        working.sort(key=lambda x: x[1])
        with open(OUTPUT, "w", encoding="utf-8") as f:
            for link, _ in working:
                f.write(link + "\n")
        print(f"\nDone. Working: {len(working)}/{len(links)}")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if not os.path.exists(OUTPUT):
            open(OUTPUT, "w").close()
        print("Script completed")
        sys.exit(0)

if __name__ == "__main__":
    main()
