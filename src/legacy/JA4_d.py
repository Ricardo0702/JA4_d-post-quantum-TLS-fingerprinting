#!/usr/bin/env python3
"""
JA4D Fingerprint Analyzer for TLS 1.3 ClientHello packets
Analyzes PCAP files to extract post-quantum cryptography readiness fingerprints
"""

from scapy.all import rdpcap, IP, TCP
import sys
from typing import Optional, Tuple, List, Set

HYBRID_GROUPS = {0x1D03D7, 0x1D03D8, 0x1D03D9, }
PURE_PQ_GROUPS = {0xFEE1, 0xFEE2, 0xFEE3}

GROUP_NAMES = {
    0x001D: 'x25519',
    0x001E: 'x448',
    0x0017: 'secp256r1',
    0x0018: 'secp384r1',
    0x0019: 'secp521r1',
    0x1D03D7: 'X25519MLKEM768',
    0x1D03D8: 'X25519MLKEM1024',
    0x1D03D9: 'P256MLKEM768',
    0xFEE1: 'ML-KEM-512',
    0xFEE2: 'ML-KEM-768',
    0xFEE3: 'ML-KEM-1024',
}


def parse_extensions(data: bytes, offset: int, end: int) -> dict:
    """Parse TLS extensions from ClientHello"""
    extensions = {}

    if offset + 2 > end:
        return extensions

    ext_total_len = int.from_bytes(data[offset:offset+2], 'big')
    offset += 2
    ext_end = min(offset + ext_total_len, end)

    while offset + 4 <= ext_end:
        ext_type = int.from_bytes(data[offset:offset+2], 'big')
        ext_len = int.from_bytes(data[offset+2:offset+4], 'big')
        offset += 4

        if offset + ext_len > ext_end:
            break

        ext_data = data[offset:offset+ext_len]
        extensions[ext_type] = ext_data
        offset += ext_len

    return extensions


def parse_supported_groups(ext_data: bytes) -> List[int]:
    """Parse supported_groups extension (0x000a)"""
    if len(ext_data) < 2:
        return []

    list_len = int.from_bytes(ext_data[0:2], 'big')
    groups = []

    for i in range(0, list_len, 2):
        if i + 2 > list_len:
            break
        group = int.from_bytes(ext_data[2+i:4+i], 'big')
        groups.append(group)

    return groups


def parse_key_share(ext_data: bytes) -> List[int]:
    """Parse key_share extension (0x0033) to get offered groups"""
    if len(ext_data) < 2:
        return []

    shares_len = int.from_bytes(ext_data[0:2], 'big')
    groups = []
    offset = 2

    while offset + 4 <= len(ext_data):
        group = int.from_bytes(ext_data[offset:offset+2], 'big')
        key_len = int.from_bytes(ext_data[offset+2:offset+4], 'big')
        groups.append(group)
        offset += 4 + key_len

    return groups


def parse_sni(ext_data: bytes) -> Optional[str]:
    """Parse server_name extension (0x0000)"""
    try:
        if len(ext_data) < 5:
            return None

        list_len = int.from_bytes(ext_data[0:2], 'big')
        name_type = ext_data[2]

        if name_type == 0:
            name_len = int.from_bytes(ext_data[3:5], 'big')
            if 5 + name_len <= len(ext_data):
                return ext_data[5:5+name_len].decode('utf-8', errors='ignore')
    except:
        pass

    return None


def parse_client_hello(payload: bytes) -> Optional[Tuple[List[int], List[int], str, bool]]:
    """
    Parse TLS 1.3 ClientHello packet
    Returns: (supported_groups, key_share_groups, sni, has_ech)
    """
    if len(payload) < 43:
        return None

    offset = 0

    if payload[offset] != 0x16:
        return None
    offset += 1

    tls_version = int.from_bytes(payload[offset:offset+2], 'big')
    if tls_version not in [0x0301, 0x0303]:
        return None
    offset += 2

    record_len = int.from_bytes(payload[offset:offset+2], 'big')
    offset += 2

    if payload[offset] != 0x01:
        return None
    offset += 1

    handshake_len = int.from_bytes(payload[offset:offset+3], 'big')
    offset += 3

    client_version = int.from_bytes(payload[offset:offset+2], 'big')
    offset += 2

    offset += 32

    if offset >= len(payload):
        return None

    session_id_len = payload[offset]
    offset += 1 + session_id_len

    if offset + 2 > len(payload):
        return None

    cipher_suites_len = int.from_bytes(payload[offset:offset+2], 'big')
    offset += 2 + cipher_suites_len

    if offset >= len(payload):
        return None

    compression_len = payload[offset]
    offset += 1 + compression_len

    if offset >= len(payload):
        return None

    extensions = parse_extensions(payload, offset, len(payload))

    supported_groups = []
    if 0x000a in extensions:
        supported_groups = parse_supported_groups(extensions[0x000a])

    key_share_groups = []
    if 0x0033 in extensions:
        key_share_groups = parse_key_share(extensions[0x0033])

    sni = None
    if 0x0000 in extensions:
        sni = parse_sni(extensions[0x0000])

    has_ech = 0xfe0d in extensions

    return (supported_groups, key_share_groups, sni or "unknown", has_ech)


def calculate_ja4d(supported_groups: List[int], key_share_groups: List[int], has_ech: bool) -> str:
    """
    Calculate JA4D fingerprint
    Format: {hybrid_count}-{pure_pq_count}-{behavior}-{ech_status}
    """
    hybrid_count = sum(1 for g in supported_groups if g in HYBRID_GROUPS)
    hybrid_count = min(hybrid_count, 9)

    pure_pq_count = sum(1 for g in supported_groups if g in PURE_PQ_GROUPS)
    pure_pq_count = min(pure_pq_count, 9)

    key_share_set = set(key_share_groups)
    supported_set = set(supported_groups)

    if key_share_set.issubset(supported_set) and len(key_share_groups) > 0:
        behavior = 'o'
    else:
        behavior = 'p'

    ech_status = 'h' if has_ech else 'n'

    return f"{hybrid_count}-{pure_pq_count}-{behavior}-{ech_status}"


def analyze_pcap(pcap_file: str, verbose: bool = False):
    """Analyze PCAP file for TLS 1.3 ClientHello packets"""
    print(f"[*] Loading PCAP file: {pcap_file}")

    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"[!] Error reading PCAP: {e}")
        return

    print(f"[*] Total packets: {len(packets)}")

    client_hellos = 0
    fingerprints = {}

    for pkt_num, pkt in enumerate(packets, 1):
        if not (IP in pkt and TCP in pkt):
            continue

        if pkt[TCP].dport not in [443, 8443] and pkt[TCP].sport not in [443, 8443]:
            continue

        payload = bytes(pkt[TCP].payload)

        if len(payload) < 100:
            continue

        parsed = parse_client_hello(payload)

        if parsed:
            supported_groups, key_share_groups, sni, has_ech = parsed
            client_hellos += 1

            ja4d = calculate_ja4d(supported_groups, key_share_groups, has_ech)

            if ja4d not in fingerprints:
                fingerprints[ja4d] = {
                    'count': 0,
                    'snis': set(),
                    'example_groups': supported_groups[:10],
                    'example_keyshare': key_share_groups
                }

            fingerprints[ja4d]['count'] += 1
            fingerprints[ja4d]['snis'].add(sni)

            if verbose:
                groups_str = ', '.join([GROUP_NAMES.get(g, f'0x{g:04x}') for g in supported_groups[:8]])
                keyshare_str = ', '.join([GROUP_NAMES.get(g, f'0x{g:04x}') for g in key_share_groups])
                print(f"\n[Packet {pkt_num}]")
                print(f"  JA4D: {ja4d}")
                print(f"  SNI: {sni}")
                print(f"  Supported Groups: [{groups_str}]")
                print(f"  Key Share Groups: [{keyshare_str}]")
                print(f"  ECH: {'Yes' if has_ech else 'No'}")

    print(f"\n{'='*70}")
    print(f"[*] Analysis Complete")
    print(f"[*] ClientHello packets found: {client_hellos}")
    print(f"[*] Unique JA4D fingerprints: {len(fingerprints)}")
    print(f"{'='*70}\n")

    if fingerprints:
        print("JA4D Fingerprints Summary:\n")
        for ja4d, info in sorted(fingerprints.items(), key=lambda x: x[1]['count'], reverse=True):
            print(f"Fingerprint: {ja4d}")
            print(f"  Count: {info['count']}")
            print(f"  SNIs: {', '.join(list(info['snis'])[:5])}")

            groups_str = ', '.join([GROUP_NAMES.get(g, f'0x{g:04x}') for g in info['example_groups']])
            print(f"  Example Groups: [{groups_str}]")

            if info['example_keyshare']:
                keyshare_str = ', '.join([GROUP_NAMES.get(g, f'0x{g:04x}') for g in info['example_keyshare']])
                print(f"  Example Key Share: [{keyshare_str}]")

            print()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ja4d_analyzer.py <pcap_file> [-v|--verbose]")
        print("\nExample: python ja4d_analyzer.py Jose.pcap -v")
        sys.exit(1)

    pcap_file = sys.argv[1]
    verbose = '-v' in sys.argv or '--verbose' in sys.argv

    analyze_pcap(pcap_file, verbose)
