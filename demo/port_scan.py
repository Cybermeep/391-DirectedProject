#!/usr/bin/env python3
"""
Simulates a TCP port scan against a target you own, for demoing the
NIDS's reconnaissance/port-scan detection.

Sends a single SYN packet to each port in a range and moves on
immediately (doesn't wait for or process responses) - equivalent in
shape to `nmap -sS`, capped to a small port range and slow enough to be
completely unremarkable load on the target.

Usage:
    python port_scan.py 192.168.1.50 --start-port 1 --end-port 200 --i-own-this-network
"""

import argparse
import random
import sys

sys.path.insert(0, ".")
from _safety import common_arg_parser, confirm_and_validate, RateLimiter

MAX_PORTS = 1000       # hard ceiling on how many ports get scanned
MAX_RATE_PER_SEC = 200


def main():
    parser = common_arg_parser("TCP port scan simulator (demo/testing only)")
    parser.add_argument("--start-port", type=int, default=1)
    parser.add_argument("--end-port", type=int, default=1024)
    parser.add_argument("--rate", type=float, default=100, help=f"Ports per second (max {MAX_RATE_PER_SEC})")
    args = parser.parse_args()

    confirm_and_validate(args)

    ports = list(range(args.start_port, args.end_port + 1))
    if len(ports) > MAX_PORTS:
        print(f"Capping scan to first {MAX_PORTS} ports (of {len(ports)} requested)")
        ports = ports[:MAX_PORTS]
    rate = min(args.rate, MAX_RATE_PER_SEC)

    try:
        from scapy.all import IP, TCP, send
    except ImportError:
        print("ERROR: scapy is required. Install it with: pip install scapy")
        sys.exit(1)

    limiter = RateLimiter(rate)
    src_port = random.randint(1024, 65535)
    print(f"Scanning {len(ports)} ports on {args.target} at ~{rate}/s ...")

    for i, port in enumerate(ports):
        pkt = IP(dst=args.target) / TCP(sport=src_port, dport=port, flags="S", seq=random.randint(0, 2**32 - 1))
        send(pkt, verbose=False)
        limiter.wait()
        if (i + 1) % 100 == 0:
            print(f"  scanned {i + 1}/{len(ports)}")

    print("Done. This shape (one source, many destination ports, no completed handshakes) is a classic port-scan signature.")


if __name__ == "__main__":
    main()
