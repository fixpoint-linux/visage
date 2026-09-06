#!/usr/bin/env python3
"""Reverse-alias relay simulator for the outbox concurrency test.

Plays the part of the local ingress (visage) that outbox's direct delivery
targets.  When a delivery arrives for a reply+<token>@<domain> recipient it
performs the reverse-route: it opens a NEW SMTP submission connection BACK to
outbox (the reply_relay hop) and only after outbox acks that submission (250)
does it send its own 250 for the original delivery.

This is exactly the topology that used to deadlock outbox's single-threaded
poll loop: outbox blocked in the first leg waiting for this server's 250, while
this server blocked waiting for outbox to accept the reply_relay submission.

One thread per inbound connection, so the later delivery of the reply_relay's
own message (which also lands here via the shared --deliver-port) is serviced
concurrently.

Usage:
  outbox_relaymx.py ADDR PORT OUTDIR SUBMIT_HOST SUBMIT_PORT USER PASS \
      REPLY_MAILFROM REPLY_RCPT
"""
import socket
import sys
import threading

sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.abspath(__file__)))
from outbox_client import Client, auth_plain, submit_data  # noqa: E402


def read_line(conn):
    buf = b""
    while not buf.endswith(b"\n"):
        ch = conn.recv(1)
        if not ch:
            return None
        buf += ch
    return buf


def reply_relay(host, port, user, passw, mailfrom, rcpt):
    raw = socket.create_connection((host, port), timeout=30)
    c = Client(raw)
    c.read_reply()                     # 220
    c.cmd("EHLO relay.test")
    c.starttls()
    c.cmd("EHLO relay.test")
    code, text = auth_plain(c, user, passw)
    if code != 235:
        raise RuntimeError(f"reply_relay AUTH failed: {code} {text}")
    code, text = submit_data(c, mailfrom, rcpt, mailfrom)
    if code != 250:
        raise RuntimeError(f"reply_relay DATA failed: {code} {text}")
    return code


class RelayMx:
    def __init__(self, addr, port, outdir, submit, reply_from, reply_rcpt):
        self.outdir = outdir
        self.submit = submit
        self.reply_from = reply_from
        self.reply_rcpt = reply_rcpt
        self.lock = threading.Lock()
        self.seq = 0
        self.ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ls.bind((addr, port))
        self.ls.listen(16)

    def serve(self):
        sys.stderr.write(f"outbox_relaymx: listening on {self.ls.getsockname()}\n")
        sys.stderr.flush()
        while True:
            conn, _ = self.ls.accept()
            threading.Thread(target=self.handle, args=(conn,), daemon=True).start()

    def record(self, body):
        with self.lock:
            self.seq += 1
            n = self.seq
        with open(f"{self.outdir}/msg-{n}.eml", "wb") as f:
            f.write(body)
        return n

    def handle(self, conn):
        try:
            conn.sendall(b"220 relaymx ESMTP ready\r\n")
            body = bytearray()
            rcpt = None
            in_data = False
            while True:
                line = read_line(conn)
                if line is None:
                    break
                raw = line.decode("ascii", "replace").rstrip("\r\n")
                cmd = raw.upper()

                if in_data:
                    if line == b".\r\n" or line == b".\n":
                        in_data = False
                        # reverse-alias reply: do the reply_relay hop FIRST,
                        # then ack the original delivery (as visage would).
                        if rcpt and rcpt.lower().startswith("reply+"):
                            host, port, user, passw = self.submit
                            reply_relay(host, port, user, passw,
                                        self.reply_from, self.reply_rcpt)
                            with open(f"{self.outdir}/reply-relay-done", "w") as f:
                                f.write("reversed\n")
                        else:
                            self.record(bytes(body))
                        conn.sendall(b"250 2.0.0 OK queued\r\n")
                        continue
                    if line.startswith(b".."):
                        line = line[1:]
                    body += line
                    continue

                if cmd.startswith("EHLO") or cmd.startswith("HELO"):
                    conn.sendall(b"250 relaymx\r\n")
                elif cmd.startswith("MAIL"):
                    conn.sendall(b"250 2.1.0 OK\r\n")
                elif cmd.startswith("RCPT"):
                    # capture the recipient (strip "RCPT TO:<...>" and params)
                    addr = raw[8:].strip()
                    if addr.startswith("<"):
                        addr = addr[1:addr.find(">")]
                    else:
                        addr = addr.split()[0] if addr else ""
                    rcpt = addr
                    conn.sendall(b"250 2.1.5 OK\r\n")
                elif cmd.startswith("DATA"):
                    conn.sendall(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    in_data = True
                elif cmd.startswith("QUIT"):
                    conn.sendall(b"221 2.0.0 Bye\r\n")
                    break
                else:
                    conn.sendall(b"250 2.0.0 OK\r\n")
        except (OSError, RuntimeError) as e:
            sys.stderr.write(f"outbox_relaymx: conn error: {e}\n")
        finally:
            try:
                conn.close()
            except OSError:
                pass


def main():
    addr = sys.argv[1]
    port = int(sys.argv[2])
    outdir = sys.argv[3]
    submit_host = sys.argv[4]
    submit_port = int(sys.argv[5])
    user = sys.argv[6]
    passw = sys.argv[7]
    reply_from = sys.argv[8]
    reply_rcpt = sys.argv[9]
    mx = RelayMx(addr, port, outdir, (submit_host, submit_port, user, passw),
                 reply_from, reply_rcpt)
    mx.serve()


if __name__ == "__main__":
    main()
