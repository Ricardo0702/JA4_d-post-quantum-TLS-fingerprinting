#!/usr/bin/env python3
"""
Generate a synthetic PCAP with varied traffic, including multiple TLS 1.3 ClientHello
variants that can be analyzed with JA4_d_v3.py.

Outputs by default:
  - ja4d_test_traffic.pcap
  - ja4d_ech_map.json

The ECH map is useful with:
  python3 JA4_d_v3.py ja4d_test_traffic.pcap --ech-map ja4d_ech_map.json

Requirements:
  pip install scapy
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import List, Sequence

from scapy.all import IP, TCP, UDP, ICMP, Raw, wrpcap  # type: ignore

REPEAT_SCENARIOS = 50
GREASE_1 = 0x0A0A
GREASE_2 = 0x1A1A

# Classical groups
X25519 = 0x001D
SECP256R1 = 0x0017
SECP384R1 = 0x0018
SECP521R1 = 0x0019

# Current hybrid groups used by JA4_d_v3.py
SECP256R1_MLKEM768 = 0x11EB
X25519_MLKEM768 = 0x11EC
SECP384R1_MLKEM1024 = 0x11ED

# Current pure PQ groups used by JA4_d_v3.py
MLKEM512 = 0x0200
MLKEM768 = 0x0201
MLKEM1024 = 0x0202

# Legacy / draft groups also understood by JA4_d_v3.py
X25519_KYBER768_DRAFT00 = 0x6399
P256_KYBER768_DRAFT00 = 0x639A
MLKEM768_PRIVATE = 0xFE31

TLS_EXT_SERVER_NAME = 0x0000
TLS_EXT_SUPPORTED_GROUPS = 0x000A
TLS_EXT_SUPPORTED_VERSIONS = 0x002B
TLS_EXT_KEY_SHARE = 0x0033
TLS_EXT_ECH = 0xFE0D


def u8(v: int) -> bytes:
    return bytes([v & 0xFF])


def u16(v: int) -> bytes:
    return int(v).to_bytes(2, "big")


def u24(v: int) -> bytes:
    return int(v).to_bytes(3, "big")


def build_extension(ext_type: int, ext_body: bytes) -> bytes:
    return u16(ext_type) + u16(len(ext_body)) + ext_body


def build_sni_ext(hostname: str) -> bytes:
    host = hostname.encode("utf-8")
    server_name = b"\x00" + u16(len(host)) + host
    body = u16(len(server_name)) + server_name
    return build_extension(TLS_EXT_SERVER_NAME, body)


def build_supported_versions_ext(versions: Sequence[int]) -> bytes:
    body = u8(2 * len(versions)) + b"".join(u16(v) for v in versions)
    return build_extension(TLS_EXT_SUPPORTED_VERSIONS, body)


def build_supported_groups_ext(groups: Sequence[int]) -> bytes:
    groups_blob = b"".join(u16(g) for g in groups)
    body = u16(len(groups_blob)) + groups_blob
    return build_extension(TLS_EXT_SUPPORTED_GROUPS, body)


def keyshare_bytes_for_group(group: int) -> bytes:
    # The analyzer only needs the group id and a valid length.
    # Sizes are loosely representative but not meant to be cryptographically real.
    if group in {MLKEM512, MLKEM768, MLKEM1024, MLKEM768_PRIVATE}:
        return bytes([0x42]) * 96
    if group in {X25519_MLKEM768, SECP256R1_MLKEM768, SECP384R1_MLKEM1024,
                 X25519_KYBER768_DRAFT00, P256_KYBER768_DRAFT00}:
        return bytes([0x24]) * 64
    if group == X25519:
        return bytes([0x19]) * 32
    if group in {SECP256R1, SECP384R1, SECP521R1}:
        return bytes([0x17]) * 65
    return bytes([0xAA]) * 16


def build_key_share_ext(groups: Sequence[int]) -> bytes:
    entries = []
    for g in groups:
        key = keyshare_bytes_for_group(g)
        entries.append(u16(g) + u16(len(key)) + key)
    blob = b"".join(entries)
    body = u16(len(blob)) + blob
    return build_extension(TLS_EXT_KEY_SHARE, body)


def build_ech_ext(config_id: int) -> bytes:
    # Matches what JA4_d_v3.py expects:
    # ext_data[0] == 0 (outer), ext_data[5] == config_id
    body = bytes([0x00, 0x00, 0x20, 0x00, 0x01, config_id & 0xFF]) + b"\x00\x02AB\x00\x02CD"
    return build_extension(TLS_EXT_ECH, body)


def build_dummy_ext(ext_type: int, data: bytes) -> bytes:
    return build_extension(ext_type, data)


def build_client_hello(
    hostname: str,
    supported_groups: Sequence[int],
    key_share_groups: Sequence[int],
    *,
    include_ech: bool = False,
    ech_config_id: int = 1,
    tls13: bool = True,
    extra_extensions: Sequence[bytes] | None = None,
) -> bytes:
    # legacy_version for TLS 1.3 ClientHello remains 0x0303
    legacy_version = b"\x03\x03"
    random_bytes = bytes(range(32))
    session_id = b"\x20" + bytes(range(32))

    cipher_suites = b"".join([
        b"\x13\x01",  # TLS_AES_128_GCM_SHA256
        b"\x13\x02",  # TLS_AES_256_GCM_SHA384
        b"\x13\x03",  # TLS_CHACHA20_POLY1305_SHA256
    ])
    cipher_suites_field = u16(len(cipher_suites)) + cipher_suites

    compression_methods = b"\x01\x00"

    exts = []
    exts.append(build_sni_ext(hostname))
    # supported_groups intentionally includes GREASE in some profiles
    exts.append(build_supported_groups_ext(supported_groups))
    if tls13:
        exts.append(build_supported_versions_ext([0x0304, 0x0303]))
    else:
        exts.append(build_supported_versions_ext([0x0303]))
    exts.append(build_key_share_ext(key_share_groups))
    # signature_algorithms (optional for realism)
    exts.append(build_dummy_ext(0x000D, u16(4) + b"\x04\x03\x08\x04"))
    # ALPN (optional, analyzer ignores it)
    exts.append(build_dummy_ext(0x0010, u16(11) + b"\x02h2\x08http/1.1"))
    if include_ech:
        exts.append(build_ech_ext(ech_config_id))
    if extra_extensions:
        exts.extend(extra_extensions)

    ext_blob = b"".join(exts)
    extensions = u16(len(ext_blob)) + ext_blob

    body = (
        legacy_version
        + random_bytes
        + session_id
        + cipher_suites_field
        + compression_methods
        + extensions
    )

    handshake = b"\x01" + u24(len(body)) + body
    record = b"\x16\x03\x03" + u16(len(handshake)) + handshake
    return record


def add_tcp_handshake(packets: List, src: str, sport: int, dst: str, dport: int, base_seq: int = 1000) -> None:
    packets.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S", seq=base_seq))
    packets.append(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="SA", seq=9000, ack=base_seq + 1))
    packets.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=base_seq + 1, ack=9001))


def add_tls_flow(
    packets: List,
    src: str,
    sport: int,
    dst: str,
    dport: int,
    tls_record: bytes,
    *,
    split_at: int | None = None,
    add_server_reply: bool = True,
    base_seq: int = 1000,
) -> None:
    add_tcp_handshake(packets, src, sport, dst, dport, base_seq=base_seq)

    client_seq = base_seq + 1
    server_seq = 9001

    if split_at is None or split_at <= 0 or split_at >= len(tls_record):
        packets.append(
            IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA", seq=client_seq, ack=server_seq) / Raw(tls_record)
        )
        client_seq += len(tls_record)
    else:
        first = tls_record[:split_at]
        second = tls_record[split_at:]
        packets.append(
            IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA", seq=client_seq, ack=server_seq) / Raw(first)
        )
        client_seq += len(first)
        packets.append(
            IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA", seq=client_seq, ack=server_seq) / Raw(second)
        )
        client_seq += len(second)

    if add_server_reply:
        # Small dummy server TLS application-data record.
        appdata = b"\x17\x03\x03\x00\x15" + b"\x00" * 21
        packets.append(
            IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="PA", seq=server_seq, ack=client_seq) / Raw(appdata)
        )
        server_seq += len(appdata)

    packets.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="FA", seq=client_seq, ack=server_seq))
    packets.append(IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="FA", seq=server_seq, ack=client_seq + 1))
    packets.append(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=client_seq + 1, ack=server_seq + 1))


def add_udp_dns_like_traffic(packets: List) -> None:
    packets.append(
        IP(src="10.10.10.10", dst="8.8.8.8") /
        UDP(sport=53000, dport=53) /
        Raw(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03org\x00\x00\x01\x00\x01")
    )
    packets.append(
        IP(src="8.8.8.8", dst="10.10.10.10") /
        UDP(sport=53, dport=53000) /
        Raw(b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x03org\x00\x00\x01\x00\x01")
    )


def add_http_like_traffic(packets: List) -> None:
    add_tcp_handshake(packets, "10.20.0.5", 51000, "93.184.216.34", 80, base_seq=3000)
    request = b"GET / HTTP/1.1\r\nHost: example.org\r\nUser-Agent: synthetic-generator\r\n\r\n"
    packets.append(
        IP(src="10.20.0.5", dst="93.184.216.34") /
        TCP(sport=51000, dport=80, flags="PA", seq=3001, ack=9001) /
        Raw(request)
    )


def add_icmp_traffic(packets: List) -> None:
    packets.append(IP(src="192.168.1.10", dst="1.1.1.1") / ICMP(type=8, code=0) / Raw(b"ping-test"))
    packets.append(IP(src="1.1.1.1", dst="192.168.1.10") / ICMP(type=0, code=0) / Raw(b"ping-test"))


def build_scenarios() -> tuple[list, dict]:
    packets: List = []

    ech_map = {
        "ech-hybrid.example.test": "h",
        "ech-classical.example.test": "c",
        "ech-pqpure.example.test": "q",
    }

    add_udp_dns_like_traffic(packets)
    add_http_like_traffic(packets)
    add_icmp_traffic(packets)

    for i in range(REPEAT_SCENARIOS):

        base_ip = 10 + i

        # 1) Classical TLS
        ch1 = build_client_hello(
            "classic-only.example.test",
            supported_groups=[GREASE_1, X25519, SECP256R1, SECP384R1, SECP521R1],
            key_share_groups=[GREASE_1, X25519],
        )
        add_tls_flow(packets, f"10.0.{base_ip}.10", 50000+i, "203.0.113.10", 443, ch1, base_seq=1000+i*100)

        # 2) Hybrid optimistic
        ch2 = build_client_hello(
            "hybrid-optimistic.example.test",
            supported_groups=[GREASE_1, X25519_MLKEM768, X25519, SECP256R1, SECP384R1],
            key_share_groups=[GREASE_1, X25519_MLKEM768, X25519],
        )
        add_tls_flow(packets, f"10.0.{base_ip}.11", 51000+i, "203.0.113.11", 443, ch2, base_seq=2000+i*100)

        # 3) Hybrid pessimistic
        ch3 = build_client_hello(
            "hybrid-pessimistic.example.test",
            supported_groups=[X25519_MLKEM768, X25519, SECP256R1],
            key_share_groups=[X25519],
        )
        add_tls_flow(packets, f"10.0.{base_ip}.12", 52000+i, "203.0.113.12", 443, ch3, base_seq=3000+i*100)

        # 4) Mixed PQ
        ch4 = build_client_hello(
            "mixed-pq.example.test",
            supported_groups=[GREASE_2, X25519_MLKEM768, MLKEM768, X25519, SECP256R1],
            key_share_groups=[X25519_MLKEM768, X25519],
        )
        add_tls_flow(packets, f"10.0.{base_ip}.13", 53000+i, "203.0.113.13", 443, ch4, base_seq=4000+i*100)

        # 5) Pure PQ optimistic
        ch5 = build_client_hello(
            "pure-pq-optimistic.example.test",
            supported_groups=[MLKEM512, MLKEM768, X25519],
            key_share_groups=[MLKEM512, MLKEM768, X25519],
        )
        add_tls_flow(packets, f"10.0.{base_ip}.14", 54000+i, "203.0.113.14", 443, ch5, base_seq=5000+i*100)

        # 6) Legacy hybrid
        ch6 = build_client_hello(
            "legacy-hybrid.example.test",
            supported_groups=[X25519_KYBER768_DRAFT00, X25519, SECP256R1],
            key_share_groups=[X25519_KYBER768_DRAFT00, X25519],
        )
        add_tls_flow(packets, f"10.0.{base_ip}.15", 55000+i, "203.0.113.15", 443, ch6, base_seq=6000+i*100)

        # 7) Legacy pure PQ
        ch7 = build_client_hello(
            "legacy-purepq.example.test",
            supported_groups=[MLKEM768_PRIVATE, X25519],
            key_share_groups=[MLKEM768_PRIVATE, X25519],
        )
        add_tls_flow(packets, f"10.0.{base_ip}.16", 56000+i, "203.0.113.16", 443, ch7, base_seq=7000+i*100)

        # 8) ECH hybrid
        ch8 = build_client_hello(
            "ech-hybrid.example.test",
            supported_groups=[X25519_MLKEM768, X25519],
            key_share_groups=[X25519_MLKEM768, X25519],
            include_ech=True,
            ech_config_id=7,
        )
        add_tls_flow(packets, f"10.0.{base_ip}.17", 57000+i, "203.0.113.17", 443, ch8, base_seq=8000+i*100)

        # 9) ECH classical
        ch9 = build_client_hello(
            "ech-classical.example.test",
            supported_groups=[X25519, SECP256R1, SECP384R1],
            key_share_groups=[X25519],
            include_ech=True,
            ech_config_id=8,
        )
        add_tls_flow(packets, f"10.0.{base_ip}.18", 58000+i, "203.0.113.18", 443, ch9, base_seq=9000+i*100)

        # 10) ECH pure PQ
        ch10 = build_client_hello(
            "ech-pqpure.example.test",
            supported_groups=[MLKEM1024, X25519],
            key_share_groups=[MLKEM1024, X25519],
            include_ech=True,
            ech_config_id=9,
        )
        add_tls_flow(packets, f"10.0.{base_ip}.19", 59000+i, "203.0.113.19", 443, ch10, base_seq=10000+i*100)

        # 11) Fragmented ClientHello
        ch11 = build_client_hello(
            "fragmented-hybrid.example.test",
            supported_groups=[X25519_MLKEM768, X25519, SECP256R1],
            key_share_groups=[X25519_MLKEM768, X25519],
        )
        add_tls_flow(packets, f"10.0.{base_ip}.20", 60000+i, "203.0.113.20", 443, ch11, split_at=65, base_seq=11000+i*100)

        # 12) TLS 1.2 ignored
        ch12 = build_client_hello(
            "tls12-should-be-ignored.example.test",
            supported_groups=[X25519, SECP256R1],
            key_share_groups=[X25519],
            tls13=False,
        )
        add_tls_flow(packets, f"10.0.{base_ip}.21", 61000+i, "203.0.113.21", 443, ch12, base_seq=12000+i*100)

        # 13) Alternate port
        ch13 = build_client_hello(
            "alt-port-8443.example.test",
            supported_groups=[SECP256R1_MLKEM768, X25519, SECP256R1],
            key_share_groups=[SECP256R1_MLKEM768, X25519],
        )
        add_tls_flow(packets, f"10.0.{base_ip}.22", 62000+i, "203.0.113.22", 8443, ch13, base_seq=13000+i*100)

    return packets, ech_map


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a synthetic PCAP with TLS ClientHello variants for JA4_d testing.")
    parser.add_argument(
        "-o", "--output",
        default="ja4d_test_traffic.pcap",
        help="Output PCAP filename (default: ja4d_test_traffic.pcap)"
    )
    parser.add_argument(
        "--ech-map",
        default="ja4d_ech_map.json",
        help="Output JSON hostname->ECH status map (default: ja4d_ech_map.json)"
    )
    args = parser.parse_args()

    packets, ech_map = build_scenarios()

    output_path = Path(args.output)
    map_path = Path(args.ech_map)

    wrpcap(str(output_path), packets)

    with map_path.open("w", encoding="utf-8") as f:
        json.dump(ech_map, f, indent=2, sort_keys=True)

    print(f"[+] Wrote PCAP: {output_path}")
    print(f"[+] Wrote ECH map: {map_path}")
    print(f"[+] Total packets: {len(packets)}")
    print()
    print("Suggested commands:")
    print(f"  python3 JA4_d_v3.py {output_path}")
    print(f"  python3 JA4_d_v3.py {output_path} --ech-map {map_path}")
    print("  python3 JA4_d_v3.py {output_path} -v")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

