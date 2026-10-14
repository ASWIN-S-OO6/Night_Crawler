#!/usr/bin/env python3
"""Minimal SNMP v2c + NBNS test responder for Night Crawler codec tests."""
import socket
import struct
import sys
import threading

SNMP_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 1161
NBNS_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1137

MIB2 = [1, 3, 6, 1, 2, 1]
WALK = [
    ([1, 3, 6, 1, 2, 1, 1, 1, 0], b"Linux testbox 6.1.0 #1 SMP x86_64"),
    ([1, 3, 6, 1, 2, 1, 1, 5, 0], b"testhost"),
    ([1, 3, 6, 1, 2, 1, 1, 6, 0], b"Server Room Rack 4"),
    # first out-of-subtree OID terminates the walk
    ([1, 3, 6, 1, 3, 1, 1], b"\x00\x01\x02"),
]

# ---------------- BER helpers ----------------

def ber_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b

def tlv(tag, content):
    return bytes([tag]) + ber_len(len(content)) + content

def ber_int(v):
    if v == 0:
        return tlv(0x02, b"\x00")
    n = (v.bit_length() + 8) // 8
    content = v.to_bytes(n, "big")
    if content[0] & 0x80:
        content = b"\x00" + content
    return tlv(0x02, content)

def ber_oid(oid):
    out = bytes([oid[0] * 40 + oid[1]])
    for v in oid[2:]:
        tmp = bytearray([v & 0x7F])
        v >>= 7
        while v:
            tmp.append((v & 0x7F) | 0x80)
            v >>= 7
        out += bytes(reversed(tmp))
    return tlv(0x06, out)

def parse_tlv(buf, i):
    tag = buf[i]; i += 1
    l = buf[i]; i += 1
    if l & 0x80:
        n = l & 0x7F
        l = int.from_bytes(buf[i:i+n], "big")
        i += n
    return tag, buf[i:i+l], i + l

def parse_oid(b):
    out = [b[0] // 40, b[0] % 40]
    v = 0
    for x in b[1:]:
        v = (v << 7) | (x & 0x7F)
        if not x & 0x80:
            out.append(v); v = 0
    return out

def value_tlv(v):
    return tlv(0x04, v)

def varbind(oid, val_bytes):
    return tlv(0x30, ber_oid(oid) + val_bytes)

def snmp_respond(data, addr, sock):
    try:
        tag, msg, _ = parse_tlv(data, 0)
        assert tag == 0x30
        _, ver, i = parse_tlv(msg, 0)          # version
        _, comm, i = parse_tlv(msg, i)          # community
        if comm != b"public":
            return None
        pdu_tag, pdu, _ = parse_tlv(msg, i)
        _, reqid, i = parse_tlv(pdu, 0)
        _, err0, i = parse_tlv(pdu, i)
        _, err1, i = parse_tlv(pdu, i)
        _, vbl, _ = parse_tlv(pdu, i)
        # parse first varbind OID
        _, vb, _ = parse_tlv(vbl, 0)
        _, oidbytes, _ = parse_tlv(vb, 0)
        req_oid = parse_oid(oidbytes)

        vbs = b""
        if pdu_tag == 0xA0:  # GET
            for oid, val in WALK:
                if oid == req_oid:
                    vbs = varbind(oid, value_tlv(val))
                    break
            if not vbs:
                vbs = varbind(req_oid, tlv(0x05, b""))
        elif pdu_tag == 0xA5:  # GETBULK
            # return next entries after req_oid
            idx = 0
            for k, (oid, val) in enumerate(WALK):
                if oid > req_oid:
                    idx = k
                    break
            else:
                idx = len(WALK)
            for oid, val in WALK[idx:idx + 3]:
                vbs += varbind(oid, value_tlv(val))
        elif pdu_tag == 0xA1:  # GETNEXT
            for oid, val in WALK:
                if oid > req_oid:
                    vbs = varbind(oid, value_tlv(val))
                    break

        resp_pdu = tlv(0xA2, ber_int(int.from_bytes(reqid, "big") if reqid else 1)
                       + ber_int(0) + ber_int(0) + tlv(0x30, vbs))
        resp = tlv(0x30, ber_int(1) + tlv(0x04, comm) + resp_pdu)
        sock.sendto(resp, addr)
    except Exception as e:
        print("snmp responder error:", e, file=sys.stderr)

# ---------------- NBNS helpers ----------------

def nbns_name(s):
    nb = s.encode()[:15].ljust(16, b" ")
    enc = bytes([32])
    for b in nb:
        enc += bytes([0x41 + (b >> 4), 0x41 + (b & 0x0F)])
    return enc + b"\x00"

def skip_name(buf, p):
    if buf[p] == 0xC0:
        return p + 2
    p += 1 + buf[p]
    while buf[p] != 0:
        p += 1 + buf[p]
    return p + 1

def nbns_respond(data, addr, sock):
    if len(data) < 12:
        return
    tid = data[:2]
    p = skip_name(data, 12)
    p += 4  # type + class
    names = [(b"TESTBOX".ljust(15), 0x00, 0x0400), (b"TESTBOX".ljust(15), 0x20, 0x0400),
             (b"WORKGROUP".ljust(15), 0x1D, 0x0000), (b"WORKGROUP".ljust(15), 0x1E, 0xC000)]
    rdata = bytes([len(names)])
    for name, suffix, flags in names:
        rdata += name + bytes([suffix]) + struct.pack(">H", flags)
    rdata += bytes([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x42])  # MAC
    rdata += b"\x00" * 18  # statistics
    answer = nbns_name("*") + struct.pack(">HHIH", 0x21, 1, 0, len(rdata)) + rdata
    header = tid + struct.pack(">HHHHH", 0x8500, 0, 1, 0, 0)
    sock.sendto(header + answer, addr)

def main():
    snmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    snmp.bind(("127.0.0.1", SNMP_PORT))
    nbns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    nbns.bind(("127.0.0.1", NBNS_PORT))

    def serve(s, handler):
        while True:
            data, addr = s.recvfrom(65535)
            handler(data, addr, s)

    threading.Thread(target=serve, args=(snmp, snmp_respond), daemon=True).start()
    threading.Thread(target=serve, args=(nbns, nbns_respond), daemon=True).start()
    print(f"ready snmp={SNMP_PORT} nbns={NBNS_PORT}", flush=True)
    threading.Event().wait()

main()
