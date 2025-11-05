#!/bin/bash
# Start all 3 local DNS servers in background (using fast multi-threaded version)

echo "Starting fast multi-threaded local DNS servers..."

# Start server 1 (forwards to Google DNS)
python3 dns_server_fast.py 1 > /tmp/dns_server1.log 2>&1 &
SERVER1_PID=$!
echo "Fast Server 1 (port 5354) started with PID $SERVER1_PID"

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

echo "All DNS servers started!"
echo "To stop them, run: kill \$(cat /tmp/dns_servers.pids)"

# Verify they're running
echo ""
echo "Checking if servers are listening..."
netstat -uln | grep -E ":(5354|5355|5356)" || ss -uln | grep -E ":(5354|5355|5356)"

