#!/usr/bin/env python3
"""
A tiny TCP listener to run ON the machine hosting the NIDS backend during
the demo, so the attacker/benign traffic scripts have a real open port to
talk to (completed handshakes for benign traffic, a live target for the
scan/flood scripts). Not part of the NIDS app itself 
"""

import argparse
import socket
import threading


def handle_client(conn, addr):
    try:
        conn.settimeout(2)
        data = conn.recv(1024)
        conn.sendall(b"ack\n")
    except Exception:
        pass
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description="Demo TCP listener")
    parser.add_argument("--port", type=int, default=8899)
    parser.add_argument("--host", default="0.0.0.0")
    args = parser.parse_args()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.host, args.port))
    server.listen(20)
    print(f"Demo target listener up on {args.host}:{args.port} (Ctrl+C to stop)")

    try:
        while True:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("Stopping.")
    finally:
        server.close()


if __name__ == "__main__":
    main()
