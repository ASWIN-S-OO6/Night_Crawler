#!/usr/bin/env python3
"""Minimal authoritative DNS server speaking AXFR over TCP for codec tests."""
import socket
import struct
import sys
import threading

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 15300


def name_bytes(name):
    out = b""
    for label in name.strip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def rr(name, rtype, rdata):
    return name_bytes(name) + struct.pack(">HHIH", rtype, 1, 3600, len(rdata)) + rdata


def a(ip):
    return socket.inet_aton(ip)


def soa(zone):
    return name_bytes("ns1." + zone) + name_bytes("hostmaster." + zone) + struct.pack(">IIIII", 2024010101, 7200, 3600, 1209600, 3600)


def build_response(qid, zone, refuse=False):
    if refuse:
        # rcode 5 = REFUSED, no answers
        return struct.pack(">HHHHHH", qid, 0x8005, 0, 0, 0, 0)
    # one message containing: SOA + A + MX + NS + TXT + SOA (end marker)
    answers = b""
    answers += rr(zone, 6, soa(zone))
    answers += rr("www." + zone, 1, a("192.0.2.10"))
    answers += rr("mail." + zone, 1, a("192.0.2.20"))
    answers += rr(zone, 15, struct.pack(">H", 10) + name_bytes("mail." + zone))
    answers += rr("ns1." + zone, 2, name_bytes("ns1." + zone))
    answers += rr(zone, 16, bytes([11]) + b"v=spf1 -all")
    answers += rr(zone, 6, soa(zone))
    header = struct.pack(">HHHHHH", qid, 0x8000, 1, 7, 0, 0)
    question = name_bytes(zone) + struct.pack(">HH", 252, 1)
    return header + question + answers


def handle(conn):
    try:
        data = conn.recv(2)
        if len(data) < 2:
            return
        (qlen,) = struct.unpack(">H", data)
        q = conn.recv(qlen)
        qid = struct.unpack(">H", q[:2])[0]
        # zone = last non-null labels; simple parse: qname starts at offset 12
        p = 12
        labels = []
        while q[p] != 0:
            labels.append(q[p + 1:p + 1 + q[p]].decode())
            p += 1 + q[p]
        zone = ".".join(labels)
        refuse = zone == "refused.example"
        msg = build_response(qid, zone, refuse)
        conn.sendall(struct.pack(">H", len(msg)) + msg)
    except Exception as e:
        print("axfr responder error:", e, file=sys.stderr, flush=True)
    finally:
        conn.close()


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", PORT))
    srv.listen(8)
    print(f"ready axfr={PORT}", flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


main()
