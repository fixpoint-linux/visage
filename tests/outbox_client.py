#!/usr/bin/env python3
"""SMTP submission client driver for the outbox integration test.

Drives one scenario per invocation and prints the final reply code + text on
stdout so the shell harness can assert.  Supports STARTTLS and implicit TLS
(server cert is NOT verified in these loopback tests).

Usage:
  outbox_client.py <host> <port> <scenario> [arg ...]
  scenarios:
    starttls-auth  user pass   -> STARTTLS + EHLO + AUTH PLAIN, print 235/code
    plaintext-auth user pass   -> plaintext EHLO + AUTH PLAIN, print code (530)
    implicit-auth  user pass   -> implicit TLS, EHLO, AUTH PLAIN
    submit  user pass mailfrom rcpt  -> auth, MAIL/RCPT/DATA, print final code
    submit-large user pass mailfrom rcpt [body_size] -> auth, MAIL/RCPT/DATA
        with a dot-safe body of body_size bytes (default 1600000), print code
    from-mismatch user pass mailfrom rcpt -> DATA with From: me@evil.com
    unauthed-rcpt  mailfrom rcpt -> no auth: MAIL then RCPT (print RCPT code)
    auth-login user pass       -> STARTTLS + AUTH LOGIN (two-step)
    bad-mailfrom user pass mailfrom -> AUTH then MAIL FROM:<mailfrom> (expect 554)
"""
import base64
import socket
import ssl
import sys


class Client:
    def __init__(self, sock):
        self.sock = sock
        self.buf = b""

    def _readline(self):
        while b"\n" not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise EOFError("connection closed")
            self.buf += chunk
        line, self.buf = self.buf.split(b"\n", 1)
        return line.rstrip(b"\r")

    def read_reply(self):
        first = None
        while True:
            line = self._readline()
            code = int(line[:3])
            if first is None:
                first = code
                text = line[4:]
            elif code != first:
                raise RuntimeError(f"reply code changed {first}->{code}")
            if len(line) > 3 and line[3:4] == b" ":
                return first, text.decode("utf-8", "replace")

    def cmd(self, s):
        self.sock.sendall(s.encode("ascii") + b"\r\n")
        return self.read_reply()

    def starttls(self):
        code, text = self.cmd("STARTTLS")
        if code != 220:
            return code, text
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.sock = ctx.wrap_socket(self.sock, server_hostname="localhost")
        self.buf = b""
        return code, text


def auth_plain(c, user, passw):
    blob = base64.b64encode(b"\0" + user.encode() + b"\0" + passw.encode()).decode()
    return c.cmd("AUTH PLAIN " + blob)


def auth_login(c, user, passw):
    code, _ = c.cmd("AUTH LOGIN")
    if code != 334:
        return code, ""
    code, _ = c.cmd(base64.b64encode(user.encode()).decode())
    if code != 334:
        return code, ""
    return c.cmd(base64.b64encode(passw.encode()).decode())


def submit_data(c, mailfrom, rcpt, from_hdr, body="Hello outbox\r\n"):
    c.cmd(f"MAIL FROM:<{mailfrom}>")
    code, text = c.cmd(f"RCPT TO:<{rcpt}>")
    if code != 250:
        return code, text
    code, text = c.cmd("DATA")
    if code != 354:
        return code, text
    msg = (f"From: {from_hdr}\r\n"
           f"To: <{rcpt}>\r\n"
           "Subject: outbox test\r\n"
           "Message-ID: <outbox-test@jaye.ch>\r\n"
           "\r\n"
           f"{body}")
    # dot-stuff any leading-dot lines
    lines = msg.split("\r\n")
    stuffed = []
    for ln in lines:
        if ln.startswith("."):
            ln = "." + ln
        stuffed.append(ln)
    payload = "\r\n".join(stuffed)
    c.sock.sendall(payload.encode("utf-8") + b"\r\n.\r\n")
    return c.read_reply()


def submit_large(c, mailfrom, rcpt, body_size):
    """Submit a message whose body is exactly body_size bytes (dot-safe, no
    leading-dot lines).  Returns the final DATA reply (code, text)."""
    c.cmd(f"MAIL FROM:<{mailfrom}>")
    code, text = c.cmd(f"RCPT TO:<{rcpt}>")
    if code != 250:
        return code, text
    code, text = c.cmd("DATA")
    if code != 354:
        return code, text
    header = (f"From: <{mailfrom}>\r\n"
              f"To: <{rcpt}>\r\n"
              "Subject: outbox large test\r\n"
              "Message-ID: <outbox-large@jaye.ch>\r\n"
              "\r\n")
    # 60-byte lines ("x"*58 + CRLF): no leading dots, so no dot-stuffing.
    line = "x" * 58 + "\r\n"
    body = (line * (body_size // len(line)) +
            ("y" * (body_size % len(line))))
    payload = header + body
    c.sock.sendall(payload.encode("utf-8") + b"\r\n.\r\n")
    return c.read_reply()


def main():
    host, port, scenario = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    args = sys.argv[4:]

    raw = socket.create_connection((host, port), timeout=30)
    c = Client(raw)

    if scenario == "implicit-auth":
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        c.sock = ctx.wrap_socket(c.sock, server_hostname="localhost")
        c.buf = b""
        code, text = c.read_reply()  # 220
        c.cmd("EHLO client.test")
        code, text = auth_plain(c, args[0], args[1])
        print(code, text)

    elif scenario == "starttls-auth":
        c.read_reply()
        c.cmd("EHLO client.test")
        code, _ = c.starttls()
        c.cmd("EHLO client.test")
        code, text = auth_plain(c, args[0], args[1])
        print(code, text)

    elif scenario == "auth-login":
        c.read_reply()
        c.cmd("EHLO client.test")
        c.starttls()
        c.cmd("EHLO client.test")
        code, text = auth_login(c, args[0], args[1])
        print(code, text)

    elif scenario == "plaintext-auth":
        c.read_reply()
        c.cmd("EHLO client.test")
        code, text = auth_plain(c, args[0], args[1])
        print(code, text)

    elif scenario == "submit":
        c.read_reply()
        c.cmd("EHLO client.test")
        c.starttls()
        c.cmd("EHLO client.test")
        code, text = auth_plain(c, args[0], args[1])
        if code != 235:
            print(code, text)
            return
        code, text = submit_data(c, args[2], args[3], f"<{args[2]}>")
        print(code, text)

    elif scenario == "submit-large":
        c.read_reply()
        c.cmd("EHLO client.test")
        c.starttls()
        c.cmd("EHLO client.test")
        code, text = auth_plain(c, args[0], args[1])
        if code != 235:
            print(code, text)
            return
        body_size = int(args[4]) if len(args) > 4 else 1600000
        code, text = submit_large(c, args[2], args[3], body_size)
        print(code, text)

    elif scenario == "from-mismatch":
        c.read_reply()
        c.cmd("EHLO client.test")
        c.starttls()
        c.cmd("EHLO client.test")
        code, text = auth_plain(c, args[0], args[1])
        if code != 235:
            print(code, text)
            return
        code, text = submit_data(c, args[2], args[3], "me@evil.com")
        print(code, text)

    elif scenario == "unauthed-rcpt":
        # implicit TLS, no AUTH: MAIL should be 530 (must authenticate)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        c.sock = ctx.wrap_socket(c.sock, server_hostname="localhost")
        c.buf = b""
        c.read_reply()
        c.cmd("EHLO client.test")
        code, text = c.cmd(f"MAIL FROM:<{args[0]}>")
        print(code, text)

    elif scenario == "bad-mailfrom":
        c.read_reply()
        c.cmd("EHLO client.test")
        c.starttls()
        c.cmd("EHLO client.test")
        code, text = auth_plain(c, args[0], args[1])
        if code != 235:
            print(code, text)
            return
        code, text = c.cmd(f"MAIL FROM:<{args[2]}>")
        print(code, text)

    else:
        print("unknown scenario", scenario, file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
