#!/usr/bin/env python3
"""
Simulates a SYN-flood-shaped traffic burst against a target, for
demoing the NIDS's DoS/flood detection
"""

import argparse
import random
import sys

sys.path.insert(0, ".")
from _safety import common_arg_parser, confirm_and_validate, RateLimiter

MAX_PACKETS = 300         # hard ceiling, regardless of --count
MAX_RATE_PER_SEC = 100    # hard ceiling, regardless of --rate


def main():
    parser = common_arg_parser("SYN flood traffic simulator (demo/testing only)")
    parser.add_argument("--port", type=int, default=8899, help="Target port (default: 8899)")
    parser.add_argument("--count", type=int, default=150, help=f"Number of SYN packets to send (max {MAX_PACKETS})")
    parser.add_argument("--rate", type=float, default=50, help=f"Packets per second (max {MAX_RATE_PER_SEC})")
    args = parser.parse_args()

    confirm_and_validate(args)

    count = min(args.count, MAX_PACKETS)
    rate = min(args.rate, MAX_RATE_PER_SEC)

    try:
        from scapy.all import IP, TCP, send
    except ImportError:
        print("ERROR: scapy is required. Install it with: pip install scapy")
        sys.exit(1)

    limiter = RateLimiter(rate)
    src_port = random.randint(1024, 65535)  # fixed for the whole run - see note above
    print(f"Sending {count} SYN packets to {args.target}:{args.port} at ~{rate}/s ...")

    for i in range(count):
        pkt = IP(dst=args.target) / TCP(sport=src_port, dport=args.port, flags="S", seq=random.randint(0, 2**32 - 1))
        send(pkt, verbose=False)
        limiter.wait()
        if (i + 1) % 25 == 0:
            print(f"  sent {i + 1}/{count}")

    print(
        "Done. This should trip BOTH detection paths: the built-in 'SYN Flood' "
        "signature (RULE-001, rate-based, always active) and, if you've saved a "
        "custom rule like 'SYN_Flag_Cnt > 5' via the Rule Builder, that too - "
        "since every packet here shares one source port and lands in a single flow."
    )


if __name__ == "__main__":
    main()
