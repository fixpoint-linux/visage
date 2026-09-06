#!/usr/bin/env python3
"""Recording SMTP server (fake MX) for the outbox integration test.

Accepts one connection at a time, speaks just enough SMTP server to capture a
delivery, and records the de-dot-stuffed message to OUTDIR/msg-N.eml with CRLF
line endings PRESERVED (so a DKIM-Signature can be verified against the exact
bytes outbox signed).  Advertises STARTTLS (and serves --cert/--key) so the
outbox's opportunistic STARTTLS delivery path is exercised too; the recorded
message is always the decrypted plaintext.

Usage: outbox_fakemx.py ADDR PORT OUTDIR [--cert PEM --key PEM]
"""
import socket
import ssl
import sys


def read_line(conn):
    buf = b""
    while not buf.endswith(b"\n"):
        ch = conn.recv(1)
        if not ch:
            return None
        buf += ch
    return buf


def main():
    argv = sys.argv[1:]
    addr, port, outdir = argv[0], int(argv[1]), argv[2]
    cert = key = None
    implicit = False
    rest = argv[3:]
    i = 0
    while i < len(rest):
        if rest[i] == "--cert":
            cert = rest[i + 1]; i += 2
        elif rest[i] == "--key":
            key = rest[i + 1]; i += 2
        elif rest[i] == "--implicit":
            implicit = True; i += 1
        else:
            i += 1

    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((addr, port))
    ls.listen(8)
    sys.stderr.write(f"outbox_fakemx: listening on {addr}:{port} -> {outdir} "
                     f"tls={'on' if cert else 'off'}\n")
    sys.stderr.flush()

    seq = 0
    while True:
        conn, _ = ls.accept()
        seq += 1
        tls = False
        dlog = open(f"{outdir}/dialogue-{seq}.txt", "w")
        dlog.write("C: <connect>\n")

        if implicit:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            conn = ctx.wrap_socket(conn, server_side=True)
            tls = True
            dlog.write("S: <implicit TLS established>\n")

        conn.sendall(b"220 fakemx ESMTP ready\r\n")
        dlog.write("S: 220 fakemx ESMTP ready\n")

        body = bytearray()
        in_data = False
        try:
            while True:
                line = read_line(conn)
                if line is None:
                    break
                cmd = line.decode("ascii", "replace").rstrip("\r\n")
                dlog.write("C: " + cmd + "\n")

                if in_data:
                    if line == b".\r\n" or line == b".\n":
                        in_data = False
                        with open(f"{outdir}/msg-{seq}.eml", "wb") as f:
                            f.write(bytes(body))
                        conn.sendall(b"250 2.0.0 OK queued\r\n")
                        dlog.write("S: 250 2.0.0 OK queued\n")
                        continue
                    # de-dot-stuff
                    if line.startswith(b".."):
                        line = line[1:]
                    body += line
                    continue

                if cmd.upper().startswith("EHLO") or cmd.upper().startswith("HELO"):
                    if cert and not tls:
                        conn.sendall(b"250-fakemx\r\n250-STARTTLS\r\n250 8BITMIME\r\n")
                        dlog.write("S: 250-fakemx\nS: 250-STARTTLS\nS: 250 8BITMIME\n")
                    else:
                        conn.sendall(b"250 fakemx\r\n")
                        dlog.write("S: 250 fakemx\n")
                elif cmd.upper().startswith("STARTTLS") and cert and not tls:
                    conn.sendall(b"220 2.0.0 Ready to start TLS\r\n")
                    dlog.write("S: 220 2.0.0 Ready to start TLS\n")
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    ctx.load_cert_chain(cert, key)
                    conn = ctx.wrap_socket(conn, server_side=True)
                    tls = True
                    dlog.write("S: <TLS established>\n")
                elif cmd.upper().startswith("MAIL"):
                    conn.sendall(b"250 2.1.0 OK\r\n")
                elif cmd.upper().startswith("RCPT"):
                    conn.sendall(b"250 2.1.5 OK\r\n")
                elif cmd.upper().startswith("DATA"):
                    conn.sendall(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    in_data = True
                elif cmd.upper().startswith("QUIT"):
                    conn.sendall(b"221 2.0.0 Bye\r\n")
                    break
                elif cmd.upper().startswith("RSET") or cmd.upper().startswith("NOOP"):
                    conn.sendall(b"250 2.0.0 OK\r\n")
                else:
                    conn.sendall(b"502 5.5.1 Command not implemented\r\n")
        except (OSError, ssl.SSLError) as e:
            sys.stderr.write(f"outbox_fakemx: conn {seq} error: {e}\n")
        finally:
            dlog.close()
            try:
                conn.close()
            except OSError:
                pass


if __name__ == "__main__":
    main()
