from scapy.all import *
import random

OUTPUT = "synthetic_tls.pcap"

CLASSIC = [0x001D,0x001E,0x0017,0x0018]
HYBRID  = [0x2F39,0x2F3A,0x2F3B]
PUREPQ  = [0xFE30,0xFE31,0xFE32]

ALL_GROUPS = HYBRID + PUREPQ + CLASSIC

packets = []

for i in range(200):

    supported = random.sample(ALL_GROUPS, random.randint(3,6))
    keyshare = random.sample(supported, random.randint(1,2))

    payload = bytearray()

    payload += b'\x16\x03\x03'          # TLS record header
    payload += b'\x00\x80'              # fake length
    payload += b'\x01'                  # ClientHello
    payload += b'\x00\x00\x7c'          # handshake len
    payload += b'\x03\x03'              # TLS 1.2 version
    payload += bytes(random.getrandbits(8) for _ in range(32))

    payload += b'\x00'                  # session id

    payload += b'\x00\x04' + b'\x13\x01\x13\x02'
    payload += b'\x01\x00'

    # Extensions
    extensions = bytearray()

    # supported_groups
    sg = bytearray()
    sg += (len(supported)*2).to_bytes(2,'big')
    for g in supported:
        sg += g.to_bytes(2,'big')

    extensions += b'\x00\x0a'
    extensions += len(sg).to_bytes(2,'big')
    extensions += sg

    # key_share
    ks = bytearray()
    for g in keyshare:
        ks += g.to_bytes(2,'big')
        ks += b'\x00\x20'
        ks += bytes(32)

    ks = len(ks).to_bytes(2,'big') + ks

    extensions += b'\x00\x33'
    extensions += len(ks).to_bytes(2,'big')
    extensions += ks

    payload += len(extensions).to_bytes(2,'big')
    payload += extensions

    pkt = IP(dst="1.1.1.1")/TCP(dport=443)/Raw(bytes(payload))
    packets.append(pkt)

wrpcap(OUTPUT, packets)

print("Generated PCAP:", OUTPUT)