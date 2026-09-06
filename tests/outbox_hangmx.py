#!/usr/bin/env python3
"""Hung fake MX for the outbox concurrency test.

Accepts a connection, writes a marker file OUTDIR/accepted-N, and then never
sends a byte (no 220 greeting).  This pins outbox's delivery worker inside the
bounded connect/greeting wait so the test can prove the poll loop keeps
servicing new submissions while that delivery is stuck.
"""
import socket
import sys


def main():
    addr, port, outdir = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((addr, port))
    ls.listen(16)
    sys.stderr.write(f"outbox_hangmx: listening on {addr}:{port} -> {outdir}\n")
    sys.stderr.flush()

    seq = 0
    while True:
        conn, _ = ls.accept()
        seq += 1
        with open(f"{outdir}/accepted-{seq}", "w") as f:
            f.write("accepted\n")
        sys.stderr.write(f"outbox_hangmx: accepted conn {seq}, holding\n")
        sys.stderr.flush()
        # Hold the socket open forever without responding: any read blocks.
        try:
            while conn.recv(4096):
                pass
        except OSError:
            pass


if __name__ == "__main__":
    main()
