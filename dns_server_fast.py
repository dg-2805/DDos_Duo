#!/usr/bin/env python3
"""
High-performance multi-threaded DNS forwarder
Uses thread pool to handle multiple concurrent requests
"""

import socket
import sys
import threading
import queue
import time
import random
from concurrent.futures import ThreadPoolExecutor

# Configuration - set via command line args
UPSTREAM_DNS = "8.8.8.8"
UPSTREAM_PORT = 53
LOCAL_PORT = 5354

# Optional: multiple upstreams and algorithm
# Example usage:
#   python3 dns_server_fast.py 1 --algo latency --upstreams 8.8.8.8,1.1.1.1,9.9.9.9
LB_ALGO = "round_robin"  # round_robin | p2c | latency
UPSTREAMS = []  # List of (ip, port)
_rr_counter = 0
_ewma_latency_us = {}  # ip -> ewma microseconds
_lock = threading.Lock()

if len(sys.argv) > 1:
    # Positional SERVER_ID retained for backward compatibility
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

# Parse optional flags (very simple parser to avoid deps)
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
    # default to single upstream behavior
    UPSTREAMS = [(UPSTREAM_DNS, UPSTREAM_PORT)]

# Initialize EWMA defaults (5ms) for all configured upstreams
for ip, _port in UPSTREAMS:
    _ewma_latency_us.setdefault(ip, 5000)

# Thread pool for handling requests
MAX_WORKERS = 32  # Adjust based on CPU cores
executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)

def _select_upstream():
    global _rr_counter
    n = len(UPSTREAMS)
    if n == 1:
        return UPSTREAMS[0]
    if LB_ALGO in ("latency", "ewma"):
        # Choose lowest EWMA latency
        best = min(UPSTREAMS, key=lambda t: _ewma_latency_us.get(t[0], 5000))
        return best
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
    # round_robin
    sel = UPSTREAMS[_rr_counter % n]
    _rr_counter += 1
    return sel

def _update_ewma(ip: str, rtt_us: int):
    # EWMA with alpha = 1/8: new = (7*old + sample) / 8
    with _lock:
        old = _ewma_latency_us.get(ip, 5000)
        new = (old * 7 + rtt_us) // 8
        _ewma_latency_us[ip] = new

def forward_dns_query(query_data):
    """Forward DNS query to selected upstream (thread-safe, optimized for low latency)"""
    upstream_ip, upstream_port = _select_upstream()
    start_ns = time.monotonic_ns()
    try:
        # Create socket for upstream
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.5)  # 500ms timeout (reduced for lower latency)
        
        # Set large buffers for high throughput
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 64 * 1024)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 64 * 1024)
        
        # Send query to upstream (non-blocking if possible)
        sock.sendto(query_data, (upstream_ip, upstream_port))
        
        # Receive response with short timeout
        response, _ = sock.recvfrom(512)
        return response
    except socket.timeout:
        return None
    except Exception:
        return None
    finally:
        try:
            sock.close()
        except Exception:
            pass
        end_ns = time.monotonic_ns()
        rtt_us = max(0, (end_ns - start_ns) // 1000)
        _update_ewma(upstream_ip, rtt_us)

def handle_request(query_data, client_addr, server_sock):
    """Handle a single DNS request"""
    # Forward query
    response = forward_dns_query(query_data)
    
    if response:
        # Send response back to client
        try:
            server_sock.sendto(response, client_addr)
        except Exception as e:
            print(f"Error sending response: {e}", file=sys.stderr, flush=True)

def main():
    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Set large receive/send buffers for high throughput
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 64 * 1024)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 64 * 1024)
    
    sock.bind(("127.0.0.1", LOCAL_PORT))
    sock.setblocking(True)
    
    print(f"Fast DNS Server {SERVER_ID if len(sys.argv) > 1 else 1} starting on 127.0.0.1:{LOCAL_PORT}", flush=True)
    if len(UPSTREAMS) == 1:
        print(f"Forwarding to {UPSTREAMS[0][0]}:{UPSTREAMS[0][1]} with {MAX_WORKERS} worker threads (algo={LB_ALGO})", flush=True)
    else:
        upstreams_str = ", ".join([f"{ip}:{port}" for ip, port in UPSTREAMS])
        print(f"Load-balancing ({LB_ALGO}) across: {upstreams_str} with {MAX_WORKERS} worker threads", flush=True)
    
    try:
        while True:
            # Receive query
            data, addr = sock.recvfrom(512)
            
            # Submit to thread pool for processing (non-blocking)
            executor.submit(handle_request, data, addr, sock)
            
    except KeyboardInterrupt:
        print("\nShutting down...", flush=True)
    finally:
        executor.shutdown(wait=True)
        sock.close()

if __name__ == "__main__":
    main()

