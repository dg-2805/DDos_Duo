#!/usr/bin/env python3
"""
High-performance local DNS server using asyncio for better performance
"""

import asyncio
import socket
import struct
import sys
import time
import random

# Configuration
UPSTREAM_DNS = "8.8.8.8"
UPSTREAM_PORT = 53
LOCAL_PORT = 5354

# Optional: support multiple upstreams and algorithms
# Usage example:
#   python3 local_dns_server_fast.py 1 --algo latency --upstreams 8.8.8.8,1.1.1.1,9.9.9.9
LB_ALGO = "round_robin"  # round_robin | p2c | latency
UPSTREAMS = []  # list of (ip, port)
_rr_counter = 0
_ewma_latency_us = {}  # ip -> ewma microseconds

# Change these per server instance
if len(sys.argv) > 1:
    try:
        SERVER_ID = int(sys.argv[1])
    except Exception:
        SERVER_ID = 1
    if SERVER_ID == 1:
        UPSTREAM_DNS = "8.8.8.8"
        LOCAL_PORT = 5354
    elif SERVER_ID == 2:
        UPSTREAM_DNS = "1.1.1.1"
        LOCAL_PORT = 5355
    elif SERVER_ID == 3:
        UPSTREAM_DNS = "9.9.9.9"
        LOCAL_PORT = 5356

# Simple flag parser (no external deps)
for i, arg in enumerate(sys.argv[2:]):
    if arg == "--algo" and (i + 3) <= len(sys.argv) and sys.argv[2 + i + 1]:
        LB_ALGO = sys.argv[2 + i + 1].strip().lower()
    if arg == "--upstreams" and (i + 3) <= len(sys.argv) and sys.argv[2 + i + 1]:
        parts = sys.argv[2 + i + 1].split(",")
        for p in parts:
            p = p.strip()
            if not p:
                continue
            if ":" in p:
                host, port = p.split(":", 1)
                try:
                    UPSTREAMS.append((host.strip(), int(port)))
                except Exception:
                    pass
            else:
                UPSTREAMS.append((p, 53))

if not UPSTREAMS:
    UPSTREAMS = [(UPSTREAM_DNS, UPSTREAM_PORT)]

# Initialize EWMA defaults (5ms)
for ip, _p in UPSTREAMS:
    _ewma_latency_us.setdefault(ip, 5000)

def _select_upstream():
    global _rr_counter
    n = len(UPSTREAMS)
    if n == 1:
        return UPSTREAMS[0]
    if LB_ALGO in ("latency", "ewma"):
        return min(UPSTREAMS, key=lambda t: _ewma_latency_us.get(t[0], 5000))
    if LB_ALGO in ("p2c", "power_of_two"):
        a = random.randrange(0, n)
        b = random.randrange(0, n)
        if b == a:
            b = (a + 1) % n
        ua = UPSTREAMS[a]
        ub = UPSTREAMS[b]
        la = _ewma_latency_us.get(ua[0], 5000)
        lb = _ewma_latency_us.get(ub[0], 5000)
        return ua if la <= lb else ub
    sel = UPSTREAMS[_rr_counter % n]
    _rr_counter += 1
    return sel

def _update_ewma(ip: str, rtt_us: int):
    old = _ewma_latency_us.get(ip, 5000)
    new = (old * 7 + rtt_us) // 8
    _ewma_latency_us[ip] = new

async def forward_dns_query(query_data, client_addr):
    """Forward DNS query to selected upstream using asyncio-friendly non-blocking calls"""
    upstream_ip, upstream_port = _select_upstream()
    start_ns = time.monotonic_ns()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.5)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 64 * 1024)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 64 * 1024)
        sock.sendto(query_data, (upstream_ip, upstream_port))
        response, _ = sock.recvfrom(512)
        return response
    except Exception as e:
        print(f"Error forwarding query: {e}", file=sys.stderr)
        return None
    finally:
        try:
            sock.close()
        except Exception:
            pass
        end_ns = time.monotonic_ns()
        _update_ewma(upstream_ip, max(0, (end_ns - start_ns) // 1000))

async def handle_dns_request(reader, writer):
    """Handle incoming DNS request"""
    try:
        # Receive query
        query_data = await reader.read(512)
        
        # Forward to upstream
        response = await forward_dns_query(query_data, writer.get_extra_info('peername'))
        
        if response:
            # Send response
            writer.write(response)
            await writer.drain()
    except Exception as e:
        print(f"Error handling request: {e}", file=sys.stderr)
    finally:
        writer.close()
        await writer.wait_closed()

# UDP handler (asyncio doesn't have great UDP support, use socket)
def handle_udp_query():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 64 * 1024)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 64 * 1024)
    sock.bind(("127.0.0.1", LOCAL_PORT))
    sock.setblocking(False)
    
    loop = asyncio.get_event_loop()
    
    async def process_packets():
        # OPTIMIZED: Remove sleep delay - process continuously
        while True:
            try:
                data, addr = sock.recvfrom(512)
                if data:
                    # Forward query
                    response = await forward_dns_query(data, addr)
                    if response:
                        sock.sendto(response, addr)
            except BlockingIOError:
                # OPTIMIZED: No sleep - use asyncio.sleep(0) for immediate yield instead of blocking
                await asyncio.sleep(0)  # Yield to event loop, no delay
            except Exception as e:
                print(f"Error: {e}", file=sys.stderr)
    
    return process_packets

async def main():
    print(f"Fast Local DNS Server starting on 127.0.0.1:{LOCAL_PORT}")
    if len(UPSTREAMS) == 1:
        print(f"Forwarding to {UPSTREAMS[0][0]}:{UPSTREAMS[0][1]} (algo={LB_ALGO})")
    else:
        ups = ", ".join([f"{ip}:{port}" for ip, port in UPSTREAMS])
        print(f"Load-balancing ({LB_ALGO}) across: {ups}")
    
    await handle_udp_query()()

if __name__ == "__main__":
    asyncio.run(main())

