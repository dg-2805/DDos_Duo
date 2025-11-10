#!/bin/bash
# Start all 3 local DNS servers in background (using fast multi-threaded version)
# Server 1 uses BIND for maximum QPS, servers 2-3 use Python

echo "Starting DNS servers (BIND + Python)..."

# Create BIND runtime directory
mkdir -p /tmp/bind

# Create minimal root hints file for BIND (required for forwarding)
cat > /tmp/bind/db.root << 'EOF'
; BIND root hints (minimal for forwarding)
.                       3600000  IN  NS    A.ROOT-SERVERS.NET.
A.ROOT-SERVERS.NET.     3600000  IN  A     198.41.0.4
EOF

# Start server 1 using BIND (high-performance, forwards to Google DNS)
# Run as current user to avoid permission issues
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
named -c "$SCRIPT_DIR/named.conf.bind" -f -u $(whoami) > /tmp/dns_server1.log 2>&1 &
SERVER1_PID=$!
echo "BIND Server 1 (port 5354) started with PID $SERVER1_PID"

# Start server 2 (forwards to Cloudflare DNS)
python3 dns_server_fast.py 2 > /tmp/dns_server2.log 2>&1 &
SERVER2_PID=$!
echo "Fast Server 2 (port 5355) started with PID $SERVER2_PID"

# Start server 3 (forwards to Quad9 DNS)
python3 dns_server_fast.py 3 > /tmp/dns_server3.log 2>&1 &
SERVER3_PID=$!
echo "Fast Server 3 (port 5356) started with PID $SERVER3_PID"

# Wait a moment for servers to start
sleep 1

# Save PIDs to file for later cleanup
echo $SERVER1_PID > /tmp/dns_servers.pids
echo $SERVER2_PID >> /tmp/dns_servers.pids
echo $SERVER3_PID >> /tmp/dns_servers.pids

# Also save BIND PID separately for cleanup
echo $SERVER1_PID > /tmp/bind_server.pid

echo "All DNS servers started!"
echo "To stop them, run: kill \$(cat /tmp/dns_servers.pids)"

# Verify they're running
echo ""
echo "Checking if servers are listening..."
netstat -uln | grep -E ":(5354|5355|5356)" || ss -uln | grep -E ":(5354|5355|5356)"

