#!/usr/bin/env python3
"""
DNS Load Test - For Educational and Testing Purposes Only
USE ONLY ON SYSTEMS YOU OWN!
"""
import socket
import threading
import time
import random

class DNSLoadTester:
    def __init__(self, target_ip, target_port=53, threads=50):
        self.target_ip = target_ip
        self.target_port = target_port
        self.threads = threads
        self.running = False
        self.packets_sent = 0
        
        # Common domains for DNS queries
        self.domains = [
            b'google.com', b'facebook.com', b'youtube.com', b'yahoo.com',
            b'wikipedia.org', b'amazon.com', b'twitter.com', b'instagram.com',
            b'reddit.com', b'netflix.com', b'microsoft.com', b'apple.com'
        ]
    
    def create_dns_query(self, domain):
        """Create a simple DNS A record query"""
        transaction_id = random.randint(1, 65535)
        # DNS header: ID, Flags, QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
        header = transaction_id.to_bytes(2, 'big') + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        
        # Domain name (length-prefixed labels)
        query = b''
        for part in domain.split(b'.'):
            query += len(part).to_bytes(1, 'big') + part
        query += b'\x00'  # End of domain
        
        # Query type A (1), class IN (1)
        query += b'\x00\x01\x00\x01'
        
        return header + query
    
    def flood_worker(self, worker_id):
        """Worker thread that sends DNS queries as fast as possible"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0)
        
        while self.running:
            try:
                domain = random.choice(self.domains)
                query = self.create_dns_query(domain)
                sock.sendto(query, (self.target_ip, self.target_port))
                self.packets_sent += 1
                
                # Minimal delay for maximum throughput
                if random.random() < 0.1:  # 90% no delay
                    time.sleep(0.0001)
                    
            except Exception:
                # Expected at high rates - continue anyway
                pass
        
        sock.close()
    
    def start_attack(self, duration=30):
        """Start the load test"""
        print(f"Starting DNS load test against {self.target_ip}:{self.target_port}")
        print(f"Duration: {duration} seconds, Threads: {self.threads}")
        print("Press Ctrl+C to stop early")
        
        self.running = True
        self.packets_sent = 0
        
        # Start all worker threads
        for i in range(self.threads):
            thread = threading.Thread(target=self.flood_worker, args=(i,))
            thread.daemon = True
            thread.start()
        
        # Run for specified duration
        start_time = time.time()
        try:
            while time.time() - start_time < duration:
                elapsed = time.time() - start_time
                qps = self.packets_sent / elapsed if elapsed > 0 else 0
                print(f"\rTime: {elapsed:.1f}s | Packets: {self.packets_sent} | QPS: {qps:.0f}", end='')
                time.sleep(0.5)
        except KeyboardInterrupt:
            print("\nStopping...")
        
        self.running = False
        time.sleep(1)  # Let threads finish
        
        print(f"\nLoad test completed.")
        print(f"Total packets sent: {self.packets_sent}")
        print(f"Average QPS: {self.packets_sent / duration:.0f}")

if __name__ == "__main__":
    # WARNING: ONLY USE ON SYSTEMS YOU OWN!
    # Replace "127.0.0.1" with your load balancer's IP
    target = "127.0.0.1"
    
    tester = DNSLoadTester(
        target_ip=target,
        target_port=53,
        threads=100  # Increase for more load
    )
    
    # Run for 30 seconds
    tester.start_attack(duration=30)