#!/usr/bin/env python3
"""
Local DNS Server 1 - Forwards to Google DNS (8.8.8.8)
Runs on port 5354
"""

import socket
import struct
import sys

# Forward to Google DNS
UPSTREAM_DNS = "8.8.8.8"
UPSTREAM_PORT = 53
LOCAL_PORT = 5354

def forward_dns_query(query_data, client_addr):
    """Forward DNS query to upstream and return response"""
    try:
        # Create socket for upstream
        upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        upstream_sock.settimeout(2.0)  # 2 second timeout
        
        # Send query to upstream
        upstream_sock.sendto(query_data, (UPSTREAM_DNS, UPSTREAM_PORT))
        
        # Receive response
        response, _ = upstream_sock.recvfrom(512)
        upstream_sock.close()
        
        return response
    except Exception as e:
        print(f"Error forwarding query: {e}", file=sys.stderr)
        return None

def main():
    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", LOCAL_PORT))
    
    print(f"Local DNS Server 1 starting on 127.0.0.1:{LOCAL_PORT}")
    print(f"Forwarding to {UPSTREAM_DNS}:{UPSTREAM_PORT}")
    
    try:
        while True:
            # Receive query
            data, addr = sock.recvfrom(512)
            
            # Forward to upstream
            response = forward_dns_query(data, addr)
            
            if response:
                # Send response back to client
                sock.sendto(response, addr)
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        sock.close()

if __name__ == "__main__":
    main()

