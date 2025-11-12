### XDP-generic DNS load balancer (no NIC offload required)

This directory contains an XDP (eBPF) program that performs L4 load balancing for UDP/53 traffic:
- On ingress requests to VIP:53, it rewrites dst IP:port to a selected backend and returns XDP_PASS so the kernel routes the packet out.
- On ingress responses from backends (sport 53), it rewrites src IP to VIP (SNAT) so clients see replies from the VIP.

It attaches in generic (SKB) mode, so it works without NIC offload or driver support.

Build:
```bash
cd xdp
make
```

Attach:
```bash
# Use listen_address from config.txt as VIP, and backends from [backend] sections
sudo ./dns_lb_user --iface <IFACE> --config ../config.txt
# Or override VIP explicitly
sudo ./dns_lb_user --iface <IFACE> --config ../config.txt --vip 192.0.2.10
```

Detach:
```bash
sudo ip link set dev <IFACE> xdp off
```

Notes:
- Generic mode returns XDP_PASS; routing/transmit is handled by the kernel. Ensure your host can route to the backend IPs.
- For IPv4 UDP, the program sets UDP checksum to 0 after rewrite (valid per RFC for IPv4), avoiding compute overhead.
- Maximum 64 backends are supported by default. Adjust in `dns_lb_kern.c` and rebuild if needed.
- For local (loopback) backends, XDP won't see responses. Prefer remote backends on real interfaces for full DNAT/SNAT path.

Config:
- `listen_address` in `config.txt` acts as VIP by default.
- Backends are read from `[backend]` blocks (`ip:` and optional `port:`).
- You can add in `config.txt` (global section):
  - `xdp_enable: true`
  - `xdp_iface: eth0`
  - `xdp_mode: generic` (default)
  - `xdp_vip: 192.0.2.10` (optional override)


