"""
Shared safety rails for the demo attacker scripts in this folder.

Every script here is a *traffic-shape simulator* for a school demo of the
NIDS project: it produces packets with the statistical signature of an
attack (many SYNs, one-way traffic, a scan across ports, etc.) so the
detection pipeline has something real to catch. None of it attempts to
actually exploit, authenticate against, or damage anything - there's no
payload, no credential guessing against a real service, no amplification.

These guardrails are intentionally hard-coded (not just documented) so
the scripts can't be pointed at a machine you don't own by accident:

  - target must be a private/loopback/link-local IP address (RFC 1918,
    127.0.0.0/8, 169.254.0.0/16) - public IPs are refused outright.
  - every script has a hard packet-count and duration ceiling.
  - every script rate-limits itself.

Run these only against machines on your own network that you have
permission to test.
"""

from __future__ import annotations

import argparse
import ipaddress
import sys
import time


class UnsafeTargetError(Exception):
    pass


def assert_safe_target(ip: str) -> None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        raise UnsafeTargetError(f"'{ip}' is not a valid IP address")

    if not (addr.is_private or addr.is_loopback or addr.is_link_local):
        raise UnsafeTargetError(
            f"Refusing to target {ip} - it is not a private/loopback/link-local address.\n"
            "These scripts are for demoing your NIDS against machines you own on your\n"
            "own LAN only (e.g. 192.168.x.x, 10.x.x.x, 172.16-31.x.x, or 127.0.0.1)."
        )


def common_arg_parser(description: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "target",
        help="Target IP address on your own LAN (e.g. 192.168.1.50). Must be private/loopback.",
    )
    parser.add_argument(
        "--i-own-this-network",
        action="store_true",
        required=True,
        help="Required acknowledgment that you own/administer the target and network.",
    )
    return parser


def confirm_and_validate(args) -> None:
    assert_safe_target(args.target)
    print(f"Target: {args.target}  (validated as private/loopback/link-local)")
    print("Starting in 2 seconds - Ctrl+C to abort...")
    try:
        time.sleep(2)
    except KeyboardInterrupt:
        print("Aborted.")
        sys.exit(1)


class RateLimiter:
    """Simple token-bucket-ish limiter so a script can't exceed a packets/sec cap even if the loop runs hot."""

    def __init__(self, max_per_second: float):
        self.min_interval = 1.0 / max_per_second if max_per_second > 0 else 0
        self._last = 0.0

    def wait(self):
        if self.min_interval <= 0:
            return
        now = time.time()
        elapsed = now - self._last
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self._last = time.time()
