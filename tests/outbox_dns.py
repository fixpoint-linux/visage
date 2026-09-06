#!/usr/bin/env python3
"""Minimal authoritative DNS responder for the outbox integration test.

Serves a fixed zone over UDP so outbox's MX/A/AAAA client (which queries the
configured resolver) can be driven on loopback without touching the real
resolver.  Answers MX (15), A (1) and AAAA (28); everything else gets an
empty (NODATA) response.

Usage: outbox_dns.py ADDR PORT
       (zone is read from argv pairs below; see main)
"""
import socket
import struct
import sys

TYPE_A = 1
TYPE_MX = 15
TYPE_AAAA = 28
CLASS_IN = 1


def encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


def decode_name(data, off):
    labels = []
    while True:
        ln = data[off]
        if ln == 0:
            return ".".join(labels), off + 1
        if ln & 0xC0 == 0xC0:
            # compression pointer: only used in our own RDATA answers, which
            # point back to the question at offset 12.
            ptr = ((ln & 0x3F) << 8) | data[off + 1]
            rest, _ = decode_name(data, ptr)
            return ".".join(labels + [rest]) if labels else rest, off + 2
        labels.append(data[off + 1:off + 1 + ln].decode("ascii"))
        off += 1 + ln


def main():
    addr = sys.argv[1]
    port = int(sys.argv[2])
    # zone: name -> list of (qtype, rdata_builder)
    zone = {}
    i = 3
    while i < len(sys.argv):
        name = sys.argv[i]
        typ = sys.argv[i + 1]
        val = sys.argv[i + 2]
        zone.setdefault(name.lower(), []).append((typ, val))
        i += 3

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((addr, port))
    sys.stderr.write(f"outbox_dns: listening on {addr}:{port} zone={list(zone)}\n")
    sys.stderr.flush()

    while True:
        data, client = sock.recvfrom(4096)
        if len(data) < 12:
            continue
        qid = data[0:2]
        qname, off = decode_name(data, 12)
        qtype, qclass = struct.unpack(">HH", data[off:off + 4])

        answers = []
        for (typ, val) in zone.get(qname.lower(), []):
            if typ == "MX" and qtype == TYPE_MX:
                pref, mxhost = val.split(" ", 1)
                rdata = struct.pack(">H", int(pref)) + encode_name(mxhost)
                answers.append((TYPE_MX, rdata))
            elif typ == "A" and qtype == TYPE_A:
                rdata = socket.inet_aton(val)
                answers.append((TYPE_A, rdata))
            elif typ == "AAAA" and qtype == TYPE_AAAA:
                rdata = socket.inet_pton(socket.AF_INET6, val)
                answers.append((TYPE_AAAA, rdata))

        flags = 0x8180  # QR + RD + RA
        header = qid + struct.pack(">HHHHH", flags, 1, len(answers), 0, 0)
        question = encode_name(qname) + struct.pack(">HH", qtype, qclass)
        body = b""
        for (typ, rdata) in answers:
            body += b"\xc0\x0c"  # name pointer to the question
            body += struct.pack(">HHIH", typ, CLASS_IN, 300, len(rdata)) + rdata
        sock.sendto(header + question + body, client)


if __name__ == "__main__":
    main()
