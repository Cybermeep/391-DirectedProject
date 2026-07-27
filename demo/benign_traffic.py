#!/usr/bin/env python3
"""
Generates ordinary, completed TCP connections against a target you own -
for contrast against the attack simulators, so the demo shows the
dashboard staying quiet/green during normal traffic and lighting up only
during the attack scripts.

Usage:
    python benign_traffic.py 192.168.1.50 --port 8899 --i-own-this-network
"""

import argparse
import socket
import sys
import time

sys.path.insert(0, ".")
from _safety import common_arg_parser, confirm_and_validate

MAX_CONNECTIONS = 200


def main():
    parser = common_arg_parser("Benign traffic generator (demo contrast)")
    parser.add_argument("--port", type=int, default=8899)
    parser.add_argument("--count", type=int, default=20, help=f"Number of connections (max {MAX_CONNECTIONS})")
    parser.add_argument("--interval", type=float, default=1.0, help="Seconds between connections")
    args = parser.parse_args()

    confirm_and_validate(args)
    count = min(args.count, MAX_CONNECTIONS)

    print(f"Making {count} ordinary connections to {args.target}:{args.port} ...")
    for i in range(count):
        try:
            with socket.create_connection((args.target, args.port), timeout=2) as s:
                s.sendall(b"hello\n")
                s.recv(1024)
        except OSError as e:
            print(f"  connection {i + 1} failed (target listener running?): {e}")
        time.sleep(args.interval)

    print("Done.")


if __name__ == "__main__":
    main()
