#!/usr/bin/env python3
"""
JA4_d Fingerprint Analyzer for TLS 1.3 ClientHello packets.

Main improvements over the original prototype:
- GREASE-aware parsing.
- Correct JA4_d behavior classification (o / p / m).
- Correct count encoding (0-9, a=10+).
- Support for both current IETF code points and legacy/private-use PQ values.
- Basic TCP stream reassembly for offline PCAP analysis.
- Optional best-effort ECH kem_id classification from DNS HTTPS records.
- Optional ECH status map extraction from DNS HTTPS/SVCB answers present in the PCAP.
- Stronger bounds checking for malformed TLS structures.

It still focuses on TLS-over-TCP PCAPs. QUIC/UDP is intentionally out of scope.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from scapy.all import DNS, IP, IPv6, TCP, UDP, Raw, rdpcap  # type: ignore

LOGGER = logging.getLogger("ja4d")

TLS_HANDSHAKE = 22
CLIENT_HELLO = 1
TLS_ECH_EXT = 0xFE0D
TLS_SUPPORTED_GROUPS_EXT = 0x000A
TLS_SERVER_NAME_EXT = 0x0000
TLS_KEY_SHARE_EXT = 0x0033
TLS_SUPPORTED_VERSIONS_EXT = 0x002B
TLS_ALPN_EXT = 0x0010
TLS_SIGNATURE_ALGORITHMS_EXT = 0x000D


DNS_TYPE_HTTPS = 65
DNS_TYPE_SVCB = 64
SVCB_PARAM_ECH = 5

# Current IETF TLS ML-KEM group code points.
# Hybrid values from draft-ietf-tls-ecdhe-mlkem-04:
# SecP256r1MLKEM768 = 0x11EB, X25519MLKEM768 = 0x11EC,
# SecP384r1MLKEM1024 = 0x11ED. citeturn656766view2turn656766view3turn656766view4
CURRENT_HYBRID_GROUPS: Dict[int, str] = {
    0x11EB: "SecP256r1MLKEM768",
    0x11EC: "X25519MLKEM768",
    0x11ED: "SecP384r1MLKEM1024",
}

# Pure ML-KEM NamedGroup code points from the TLS WG slides for draft-ietf-tls-mlkem-05:
# MLKEM512=0x0200, MLKEM768=0x0201, MLKEM1024=0x0202. citeturn747191view0
CURRENT_PURE_PQ_GROUPS: Dict[int, str] = {
    0x0200: "MLKEM512",
    0x0201: "MLKEM768",
    0x0202: "MLKEM1024",
}

# Legacy / experimental / private-use values seen in prototypes and older captures.
LEGACY_HYBRID_GROUPS: Dict[int, str] = {
    0x6399: "X25519Kyber768Draft00",
    0x639A: "P256Kyber768Draft00",
    0x1D03D7: "X25519MLKEM768-legacy",
    0x1D03D8: "X25519MLKEM1024-legacy",
    0x1D03D9: "P256MLKEM768-legacy",
}

LEGACY_PURE_PQ_GROUPS: Dict[int, str] = {
    0xFE30: "ML-KEM-512-private",
    0xFE31: "ML-KEM-768-private",
    0xFE32: "ML-KEM-1024-private",
    0xFEE1: "ML-KEM-512-legacy",
    0xFEE2: "ML-KEM-768-legacy",
    0xFEE3: "ML-KEM-1024-legacy",
}

HYBRID_GROUPS: Dict[int, str] = {**CURRENT_HYBRID_GROUPS, **LEGACY_HYBRID_GROUPS}
PURE_PQ_GROUPS: Dict[int, str] = {**CURRENT_PURE_PQ_GROUPS, **LEGACY_PURE_PQ_GROUPS}
PQ_GROUPS: Set[int] = set(HYBRID_GROUPS) | set(PURE_PQ_GROUPS)

CLASSICAL_GROUP_NAMES: Dict[int, str] = {
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x0019: "secp521r1",
    0x001D: "x25519",
    0x001E: "x448",
}

GROUP_NAMES: Dict[int, str] = {
    **CLASSICAL_GROUP_NAMES,
    **HYBRID_GROUPS,
    **PURE_PQ_GROUPS,
}

# HPKE KEM identifiers mentioned in the TFG for JA4_d categorization.
ECH_CLASSICAL_KEM_IDS = {0x0010, 0x0011, 0x0012}
ECH_HYBRID_KEM_IDS = {0x0030, 0x0031, 0x0032}
ECH_PURE_PQ_KEM_IDS = {0x0040, 0x0041, 0x0042}


@dataclass
class ClientHelloInfo:
    cipher_suites: List[int]
    extension_types: List[int]
    signature_algorithms: List[int]
    alpn: str
    supported_versions: List[int]
    supported_groups: List[int]
    key_share_groups: List[int]
    sni: str
    has_ech: bool
    ech_config_id: Optional[int]
    offered_tls13: bool


@dataclass
class HandshakeRecord:
    packet_number: int
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    sni: str
    supported_groups: List[int]
    key_share_groups: List[int]
    has_ech: bool
    ech_config_id: Optional[int]
    offered_tls13: bool
    ja4: str
    ja4_d: str
    full_ja4_ja4d: str
    ech_status: str


def is_grease_value(value: int) -> bool:
    """Return True when value is a RFC 8701 GREASE pattern."""
    return 0x0A0A <= value <= 0xFAFA and (value & 0x00FF) == (value >> 8) and (value & 0x000F) == 0x0A


def encode_count(count: int) -> str:
    return "a" if count >= 10 else str(count)


def group_name(group_id: int) -> str:
    return GROUP_NAMES.get(group_id, f"0x{group_id:04x}")


def safe_slice(data: bytes, start: int, length: int) -> Optional[bytes]:
    end = start + length
    if start < 0 or length < 0 or end > len(data):
        return None
    return data[start:end]




def parse_cipher_suites_from_clienthello(handshake_body: bytes, offset: int) -> Tuple[List[int], int]:
    """Parse cipher suites from a ClientHello body and return (non-GREASE suites, new_offset)."""
    if offset + 2 > len(handshake_body):
        return [], offset
    cipher_suites_len = int.from_bytes(handshake_body[offset:offset + 2], "big")
    offset += 2
    if cipher_suites_len % 2 != 0 or offset + cipher_suites_len > len(handshake_body):
        return [], offset
    suites: List[int] = []
    for i in range(0, cipher_suites_len, 2):
        suite = int.from_bytes(handshake_body[offset + i:offset + i + 2], "big")
        if not is_grease_value(suite):
            suites.append(suite)
    return suites, offset + cipher_suites_len


def parse_extensions_ordered(data: bytes, offset: int, end: int) -> Tuple[Dict[int, bytes], List[int]]:
    """Return extension payloads and ordered non-GREASE extension type IDs."""
    extensions: Dict[int, bytes] = {}
    extension_types: List[int] = []
    ext_len_bytes = safe_slice(data, offset, 2)
    if ext_len_bytes is None:
        return extensions, extension_types

    total_len = int.from_bytes(ext_len_bytes, "big")
    offset += 2
    ext_end = min(offset + total_len, end)

    while offset + 4 <= ext_end:
        ext_type = int.from_bytes(data[offset:offset + 2], "big")
        ext_len = int.from_bytes(data[offset + 2:offset + 4], "big")
        offset += 4
        if offset + ext_len > ext_end:
            LOGGER.debug("Malformed extension: advertised len beyond extension block")
            break
        extensions[ext_type] = data[offset:offset + ext_len]
        if not is_grease_value(ext_type):
            extension_types.append(ext_type)
        offset += ext_len

    return extensions, extension_types

def parse_extensions(data: bytes, offset: int, end: int) -> Dict[int, bytes]:
    extensions: Dict[int, bytes] = {}
    ext_len_bytes = safe_slice(data, offset, 2)
    if ext_len_bytes is None:
        return extensions

    total_len = int.from_bytes(ext_len_bytes, "big")
    offset += 2
    ext_end = min(offset + total_len, end)

    while offset + 4 <= ext_end:
        ext_type = int.from_bytes(data[offset:offset + 2], "big")
        ext_len = int.from_bytes(data[offset + 2:offset + 4], "big")
        offset += 4
        if offset + ext_len > ext_end:
            LOGGER.debug("Malformed extension: advertised len beyond extension block")
            break
        extensions[ext_type] = data[offset:offset + ext_len]
        offset += ext_len

    return extensions


def parse_supported_versions(ext_data: bytes) -> List[int]:
    if not ext_data:
        return []
    vector_len = ext_data[0]
    if vector_len + 1 > len(ext_data):
        return []
    versions = []
    for i in range(1, 1 + vector_len, 2):
        if i + 2 > len(ext_data):
            break
        versions.append(int.from_bytes(ext_data[i:i + 2], "big"))
    return versions


def parse_supported_groups(ext_data: bytes) -> List[int]:
    if len(ext_data) < 2:
        return []

    list_len = int.from_bytes(ext_data[0:2], "big")
    if list_len != len(ext_data) - 2:
        list_len = min(list_len, max(0, len(ext_data) - 2))

    groups: List[int] = []
    for i in range(0, list_len, 2):
        if 2 + i + 2 > len(ext_data):
            break
        group = int.from_bytes(ext_data[2 + i:4 + i], "big")
        if is_grease_value(group):
            continue
        groups.append(group)
    return groups


def parse_key_share(ext_data: bytes) -> List[int]:
    if len(ext_data) < 2:
        return []

    shares_len = int.from_bytes(ext_data[0:2], "big")
    shares_end = min(2 + shares_len, len(ext_data))
    groups: List[int] = []
    offset = 2

    while offset + 4 <= shares_end:
        group = int.from_bytes(ext_data[offset:offset + 2], "big")
        key_len = int.from_bytes(ext_data[offset + 2:offset + 4], "big")
        offset += 4
        if offset + key_len > shares_end:
            LOGGER.debug("Malformed key_share entry: key length beyond extension")
            break
        if not is_grease_value(group):
            groups.append(group)
        offset += key_len

    return groups


def parse_sni(ext_data: bytes) -> Optional[str]:
    try:
        if len(ext_data) < 2:
            return None
        list_len = int.from_bytes(ext_data[0:2], "big")
        if list_len + 2 > len(ext_data):
            list_len = len(ext_data) - 2
        offset = 2
        end = 2 + list_len
        while offset + 3 <= end:
            name_type = ext_data[offset]
            name_len = int.from_bytes(ext_data[offset + 1:offset + 3], "big")
            offset += 3
            if offset + name_len > end:
                break
            if name_type == 0:
                return ext_data[offset:offset + name_len].decode("utf-8", errors="ignore")
            offset += name_len
    except Exception:
        LOGGER.debug("Failed to parse SNI", exc_info=True)
    return None


def parse_ech_config_id(ext_data: bytes) -> Optional[int]:
    """
    Parse outer ECHClientHello and return config_id when available.

    RFC 9849 defines encrypted_client_hello(0xfe0d) and the outer payload as:
    type(1), cipher_suite(4), config_id(1), enc<..>, payload<..>. citeturn408219view1turn295379view2
    """
    if not ext_data:
        return None
    ech_type = ext_data[0]
    if ech_type != 0:  # inner(1) has empty payload; outer(0) carries config_id.
        return None
    if len(ext_data) < 6:
        return None
    return ext_data[5]




def parse_signature_algorithms(ext_data: bytes) -> List[int]:
    if len(ext_data) < 2:
        return []
    list_len = int.from_bytes(ext_data[0:2], "big")
    list_len = min(list_len, max(0, len(ext_data) - 2))
    algs: List[int] = []
    for i in range(0, list_len, 2):
        if 2 + i + 2 > len(ext_data):
            break
        alg = int.from_bytes(ext_data[2 + i:4 + i], "big")
        if not is_grease_value(alg):
            algs.append(alg)
    return algs


def parse_alpn(ext_data: bytes) -> str:
    if len(ext_data) < 3:
        return "00"
    list_len = int.from_bytes(ext_data[0:2], "big")
    end = min(2 + list_len, len(ext_data))
    offset = 2
    if offset >= end:
        return "00"
    name_len = ext_data[offset]
    offset += 1
    if offset + name_len > end or name_len == 0:
        return "00"
    alpn = ext_data[offset:offset + name_len].decode("ascii", errors="ignore")
    return alpn[:2] if alpn else "00"


def tls_version_to_ja4(version: int) -> str:
    mapping = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10"}
    return mapping.get(version, f"{version & 0xff:02d}")


def _hash_ja4_values(values: Sequence[int]) -> str:
    if not values:
        return "000000000000"
    text = ",".join(f"{v:04x}" for v in sorted(values))
    return hashlib.sha256(text.encode("ascii")).hexdigest()[:12]


def calculate_ja4(info: "ClientHelloInfo") -> str:
    """
    Calculate a JA4-style TLS ClientHello fingerprint from the parsed ClientHello.

    The output is generated from the actual ClientHello observed in the PCAP: protocol/TLS
    version/SNI flag/counts/ALPN, followed by hashes of cipher suites and extensions plus
    signature algorithms. GREASE values are filtered before counting and hashing.
    """
    version = max(info.supported_versions) if info.supported_versions else 0x0304
    version_part = tls_version_to_ja4(version)
    sni_part = "d" if info.sni and info.sni != "unknown" else "i"
    cipher_count = min(len(info.cipher_suites), 99)
    extension_count = min(len(info.extension_types), 99)
    ja4_a = f"t{version_part}{sni_part}{cipher_count:02d}{extension_count:02d}{info.alpn or '00'}"
    ja4_b = _hash_ja4_values(info.cipher_suites)
    ja4_c_values = list(info.extension_types) + list(info.signature_algorithms)
    ja4_c = _hash_ja4_values(ja4_c_values)
    return f"{ja4_a}_{ja4_b}_{ja4_c}"

def extract_client_hello_info(handshake_body: bytes) -> Optional[ClientHelloInfo]:
    # handshake_body begins at ClientHello.legacy_version
    if len(handshake_body) < 2 + 32 + 1:
        return None

    offset = 0
    _legacy_version = int.from_bytes(handshake_body[offset:offset + 2], "big")
    offset += 2

    offset += 32  # random
    if offset >= len(handshake_body):
        return None

    session_id_len = handshake_body[offset]
    offset += 1
    if offset + session_id_len > len(handshake_body):
        return None
    offset += session_id_len

    cipher_suites, offset = parse_cipher_suites_from_clienthello(handshake_body, offset)
    if not cipher_suites and offset >= len(handshake_body):
        return None

    if offset >= len(handshake_body):
        return None
    compression_methods_len = handshake_body[offset]
    offset += 1
    if offset + compression_methods_len > len(handshake_body):
        return None
    offset += compression_methods_len

    extensions, extension_types = parse_extensions_ordered(handshake_body, offset, len(handshake_body))

    supported_groups = parse_supported_groups(extensions.get(TLS_SUPPORTED_GROUPS_EXT, b""))
    key_share_groups = parse_key_share(extensions.get(TLS_KEY_SHARE_EXT, b""))
    signature_algorithms = parse_signature_algorithms(extensions.get(TLS_SIGNATURE_ALGORITHMS_EXT, b""))
    alpn = parse_alpn(extensions.get(TLS_ALPN_EXT, b""))
    sni = parse_sni(extensions.get(TLS_SERVER_NAME_EXT, b"")) or "unknown"
    has_ech = TLS_ECH_EXT in extensions
    ech_config_id = parse_ech_config_id(extensions.get(TLS_ECH_EXT, b"")) if has_ech else None

    versions = parse_supported_versions(extensions.get(TLS_SUPPORTED_VERSIONS_EXT, b""))
    offered_tls13 = 0x0304 in versions

    return ClientHelloInfo(
        cipher_suites=cipher_suites,
        extension_types=extension_types,
        signature_algorithms=signature_algorithms,
        alpn=alpn,
        supported_versions=versions,
        supported_groups=supported_groups,
        key_share_groups=key_share_groups,
        sni=sni,
        has_ech=has_ech,
        ech_config_id=ech_config_id,
        offered_tls13=offered_tls13,
    )


def iter_client_hello_messages(stream: bytes) -> Iterable[bytes]:
    """Yield complete ClientHello handshake bodies found inside TLS records."""
    offset = 0
    while offset + 5 <= len(stream):
        content_type = stream[offset]
        legacy_record_version = int.from_bytes(stream[offset + 1:offset + 3], "big")
        record_len = int.from_bytes(stream[offset + 3:offset + 5], "big")
        record_end = offset + 5 + record_len

        if record_end > len(stream):
            break

        record_payload = stream[offset + 5:record_end]

        if content_type == TLS_HANDSHAKE and legacy_record_version in {0x0301, 0x0302, 0x0303, 0x0304}:
            hs_offset = 0
            while hs_offset + 4 <= len(record_payload):
                hs_type = record_payload[hs_offset]
                hs_len = int.from_bytes(record_payload[hs_offset + 1:hs_offset + 4], "big")
                hs_start = hs_offset + 4
                hs_end = hs_start + hs_len
                if hs_end > len(record_payload):
                    break
                if hs_type == CLIENT_HELLO:
                    yield record_payload[hs_start:hs_end]
                hs_offset = hs_end

        offset = record_end


@dataclass(frozen=True)
class FlowKey:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int


@dataclass
class TcpFragment:
    seq: int
    payload: bytes
    packet_number: int


def canonical_flow_from_packet(pkt) -> Optional[Tuple[FlowKey, TcpFragment]]:
    if TCP not in pkt:
        return None

    ip_layer = None
    if IP in pkt:
        ip_layer = pkt[IP]
        src_ip, dst_ip = ip_layer.src, ip_layer.dst
    elif IPv6 in pkt:
        ip_layer = pkt[IPv6]
        src_ip, dst_ip = ip_layer.src, ip_layer.dst
    else:
        return None

    tcp = pkt[TCP]
    payload = bytes(tcp.payload)
    if not payload:
        return None

    key = FlowKey(src_ip=src_ip, src_port=int(tcp.sport), dst_ip=dst_ip, dst_port=int(tcp.dport))
    frag = TcpFragment(seq=int(tcp.seq), payload=payload, packet_number=getattr(pkt, "number", 0))
    return key, frag


def reassemble_fragments(fragments: Sequence[TcpFragment]) -> bytes:
    if not fragments:
        return b""

    ordered = sorted(fragments, key=lambda f: (f.seq, len(f.payload)))
    assembled = bytearray()
    expected_seq: Optional[int] = None

    for frag in ordered:
        if not frag.payload:
            continue
        if expected_seq is None:
            assembled.extend(frag.payload)
            expected_seq = frag.seq + len(frag.payload)
            continue

        if frag.seq >= expected_seq:
            if frag.seq > expected_seq:
                # Gap detected. Preserve only contiguous bytes to avoid corrupt parsing.
                LOGGER.debug("TCP gap detected during reassembly: seq=%s expected=%s", frag.seq, expected_seq)
                break
            assembled.extend(frag.payload)
            expected_seq = frag.seq + len(frag.payload)
            continue

        # Overlap / retransmission
        overlap = expected_seq - frag.seq
        if overlap < len(frag.payload):
            assembled.extend(frag.payload[overlap:])
            expected_seq += len(frag.payload) - overlap

    return bytes(assembled)


def build_tcp_streams(packets) -> Dict[FlowKey, List[TcpFragment]]:
    streams: Dict[FlowKey, List[TcpFragment]] = {}
    for pkt in packets:
        parsed = canonical_flow_from_packet(pkt)
        if not parsed:
            continue
        key, frag = parsed
        streams.setdefault(key, []).append(frag)
    return streams


class EchResolver:
    def __init__(self, static_map: Optional[Dict[str, str]] = None, enable_dns: bool = False):
        self.static_map = {k.lower(): v for k, v in (static_map or {}).items()}
        self.enable_dns = enable_dns
        self._cache: Dict[Tuple[str, Optional[int]], str] = {}
        self._dns_resolver = None
        if enable_dns:
            try:
                import dns.rdatatype  # type: ignore
                import dns.resolver  # type: ignore

                self._dns_resolver = dns.resolver.Resolver()
                self._https_rdatatype = dns.rdatatype.HTTPS
            except Exception:
                LOGGER.warning("dnspython not available; live DNS ECH resolution disabled")
                self.enable_dns = False

    def resolve(self, hostname: str, has_ech: bool, config_id: Optional[int]) -> str:
        if not has_ech:
            return "n"

        hostname = (hostname or "").strip().rstrip(".").lower()
        if not hostname or hostname == "unknown":
            return "n"

        cached = self._cache.get((hostname, config_id))
        if cached is not None:
            return cached

        if hostname in self.static_map:
            status = self.static_map[hostname]
            if status in {"c", "h", "q", "n"}:
                self._cache[(hostname, config_id)] = status
                return status

        if self.enable_dns and self._dns_resolver is not None:
            status = self._resolve_via_https_rr(hostname, config_id)
            self._cache[(hostname, config_id)] = status
            return status

        self._cache[(hostname, config_id)] = "n"
        return "n"

    def _resolve_via_https_rr(self, hostname: str, config_id: Optional[int]) -> str:
        try:
            answers = self._dns_resolver.resolve(hostname, self._https_rdatatype)
        except Exception as exc:
            LOGGER.debug("HTTPS RR lookup failed for %s: %s", hostname, exc)
            return "n"

        for answer in answers:
            params = getattr(answer, "params", None)
            if not params:
                continue
            ech_bytes = None
            for key, value in params.items():
                key_name = str(key).lower()
                if "ech" in key_name:
                    ech_bytes = getattr(value, "ech", None) or getattr(value, "value", None) or bytes(value)
                    break
            if not ech_bytes:
                continue

            kem_id = extract_kem_id_from_echconfig_list(bytes(ech_bytes), config_id)
            if kem_id is None:
                continue
            return map_kem_id_to_ech_status(kem_id)

        return "n"


def extract_kem_id_from_echconfig_list(ech_config_list: bytes, desired_config_id: Optional[int]) -> Optional[int]:
    """Parse ECHConfigList and return the kem_id for the requested config_id."""
    if len(ech_config_list) < 2:
        return None

    total_len = int.from_bytes(ech_config_list[0:2], "big")
    end = min(len(ech_config_list), 2 + total_len)
    offset = 2

    while offset + 4 <= end:
        version = int.from_bytes(ech_config_list[offset:offset + 2], "big")
        cfg_len = int.from_bytes(ech_config_list[offset + 2:offset + 4], "big")
        offset += 4
        if offset + cfg_len > end:
            break
        if version == 0xFE0D and cfg_len >= 3:
            config_id = ech_config_list[offset]
            kem_id = int.from_bytes(ech_config_list[offset + 1:offset + 3], "big")
            if desired_config_id is None or config_id == desired_config_id:
                return kem_id
        offset += cfg_len

    return None


def map_kem_id_to_ech_status(kem_id: int) -> str:
    if kem_id in ECH_CLASSICAL_KEM_IDS:
        return "c"
    if kem_id in ECH_HYBRID_KEM_IDS:
        return "h"
    if kem_id in ECH_PURE_PQ_KEM_IDS:
        return "q"
    return "n"




def _normalize_hostname(name: object) -> str:
    """Return a lower-case hostname without a trailing dot from Scapy/dnspython values."""
    if isinstance(name, bytes):
        text = name.decode("utf-8", errors="ignore")
    else:
        text = str(name)
    return text.strip().rstrip(".").lower()


def _dns_name_to_text_from_rdata(data: bytes, offset: int = 0) -> Tuple[str, int]:
    """
    Decode a domain name inside HTTPS/SVCB RDATA.

    SVCB/HTTPS TargetName is normally uncompressed in modern records. This parser also
    handles a compression pointer defensively by stopping at the pointer; the target name
    itself is not needed for JA4_d, only the offset after the TargetName.
    """
    labels: List[str] = []
    pos = offset
    while pos < len(data):
        length = data[pos]
        pos += 1
        if length == 0:
            break
        if length & 0xC0 == 0xC0:
            # Compression pointer: consume the second byte and stop. We do not need to
            # follow it to parse the following SvcParam list correctly.
            if pos < len(data):
                pos += 1
            break
        if pos + length > len(data):
            return "", len(data)
        labels.append(data[pos:pos + length].decode("utf-8", errors="ignore"))
        pos += length
    return ".".join(label for label in labels if label), pos


def extract_ech_param_from_https_rdata(rdata: bytes) -> Optional[bytes]:
    """
    Extract the ECHConfigList SvcParam value from raw HTTPS/SVCB RDATA.

    HTTPS/SVCB RDATA layout:
      SvcPriority(2) | TargetName(variable) | SvcParams*
    Each SvcParam is:
      SvcParamKey(2) | SvcParamValue length(2) | SvcParamValue
    The ECH parameter key is 5.
    """
    if len(rdata) < 3:
        return None

    # Skip SvcPriority.
    offset = 2
    _target, offset = _dns_name_to_text_from_rdata(rdata, offset)

    while offset + 4 <= len(rdata):
        key = int.from_bytes(rdata[offset:offset + 2], "big")
        value_len = int.from_bytes(rdata[offset + 2:offset + 4], "big")
        offset += 4
        if offset + value_len > len(rdata):
            break
        value = rdata[offset:offset + value_len]
        offset += value_len
        if key == SVCB_PARAM_ECH:
            return value
    return None


def _coerce_dns_rdata_to_bytes(rr) -> Optional[bytes]:
    """Best-effort conversion of a Scapy DNS RR RDATA field to bytes."""
    for attr in ("rdata", "rdata_raw"):
        if hasattr(rr, attr):
            value = getattr(rr, attr)
            try:
                if isinstance(value, bytes):
                    return value
                if isinstance(value, str):
                    return value.encode("latin1", errors="ignore")
                return bytes(value)
            except Exception:
                pass
    try:
        raw = bytes(rr)
        rdlen = int(getattr(rr, "rdlen", 0) or 0)
        if rdlen and len(raw) >= rdlen:
            return raw[-rdlen:]
    except Exception:
        pass
    return None


def _iter_dns_answers(dns_layer) -> Iterable[object]:
    """Yield answer RRs from a Scapy DNS layer safely."""
    try:
        ancount = int(getattr(dns_layer, "ancount", 0) or 0)
        current = getattr(dns_layer, "an", None)

        for _ in range(ancount):
            if current is None:
                break

            try:
                rr_type = getattr(current, "type", None)
            except Exception:
                break

            if rr_type is None:
                break

            yield current

            try:
                current = getattr(current, "payload", None)
            except Exception:
                break

    except Exception:
        return


def build_ech_map_from_dns_packets(packets) -> Dict[str, str]:
    """
    Build a hostname -> ECH status map from HTTPS/SVCB DNS answers present in a PCAP.

    This is a best-effort offline method. It only works when the capture contains DNS
    responses carrying HTTPS/SVCB records with ECHConfig data. Encrypted DNS protocols
    such as DoH/DoT cannot be parsed by this function.
    """
    ech_map: Dict[str, str] = {}

    for pkt in packets:
        if DNS not in pkt:
            continue
        dns_layer = pkt[DNS]
        if int(getattr(dns_layer, "qr", 0) or 0) != 1:
            continue

        for rr in _iter_dns_answers(dns_layer):
            try:
                rr_type = int(getattr(rr, "type", -1) or -1)
            except Exception:
                continue
            if rr_type not in {DNS_TYPE_HTTPS, DNS_TYPE_SVCB}:
                continue

            hostname = _normalize_hostname(getattr(rr, "rrname", ""))
            if not hostname:
                continue

            rdata = _coerce_dns_rdata_to_bytes(rr)
            if not rdata:
                continue

            ech_config_list = extract_ech_param_from_https_rdata(rdata)
            if not ech_config_list:
                continue

            kem_id = extract_kem_id_from_echconfig_list(ech_config_list, desired_config_id=None)
            if kem_id is None:
                continue

            status = map_kem_id_to_ech_status(kem_id)
            if status in {"c", "h", "q"}:
                ech_map[hostname] = status
                LOGGER.debug("PCAP DNS ECH map: %s -> %s (kem_id=0x%04x)", hostname, status, kem_id)

    return ech_map

def classify_behavior(supported_groups: Sequence[int], key_share_groups: Sequence[int]) -> str:
    pq_supported = {g for g in supported_groups if g in PQ_GROUPS}
    pq_keyshare = {g for g in key_share_groups if g in PQ_GROUPS}

    if not pq_supported:
        return "p"
    if not pq_keyshare:
        return "p"
    if pq_keyshare == pq_supported:
        return "o"
    if pq_keyshare < pq_supported:
        return "m"
    # Defensive fallback if malformed key_share advertises a PQ group that is absent from supported_groups.
    return "m"


def calculate_ja4d(
    supported_groups: Sequence[int],
    key_share_groups: Sequence[int],
    ech_status: str,
) -> str:
    hybrid_count = sum(1 for g in supported_groups if g in HYBRID_GROUPS)
    pure_pq_count = sum(1 for g in supported_groups if g in PURE_PQ_GROUPS)
    behavior = classify_behavior(supported_groups, key_share_groups)
    return f"{encode_count(hybrid_count)}-{encode_count(pure_pq_count)}-{behavior}-{ech_status}"


def analyze_pcap(
    pcap_file: str,
    verbose: bool = False,
    enable_dns: bool = False,
    ech_map_file: Optional[str] = None,
    dns_from_pcap: bool = False,
    dump_ech_map_file: Optional[str] = None,
    include_all_ports: bool = False,
) -> List[HandshakeRecord]:
    LOGGER.info("Loading PCAP file: %s", pcap_file)
    packets = rdpcap(pcap_file)
    LOGGER.info("Total packets: %d", len(packets))

    static_map: Dict[str, str] = {}

    if dns_from_pcap:
        pcap_ech_map = build_ech_map_from_dns_packets(packets)
        static_map.update(pcap_ech_map)
        LOGGER.info("ECH entries extracted from DNS HTTPS/SVCB records in PCAP: %d", len(pcap_ech_map))

    if ech_map_file:
        with open(ech_map_file, "r", encoding="utf-8") as f:
            file_map = json.load(f)
        static_map.update({str(k).lower(): str(v) for k, v in file_map.items()})
        LOGGER.info("ECH entries loaded from auxiliary map: %d", len(file_map))

    if dump_ech_map_file:
        with open(dump_ech_map_file, "w", encoding="utf-8") as f:
            json.dump(static_map, f, indent=2, sort_keys=True)
        LOGGER.info("Wrote combined ECH map to: %s", dump_ech_map_file)

    ech_resolver = EchResolver(static_map=static_map, enable_dns=enable_dns)
    streams = build_tcp_streams(packets)

    results: List[HandshakeRecord] = []

    for flow_key, fragments in streams.items():
        if not include_all_ports and flow_key.dst_port not in {443, 8443}:
            continue

        stream = reassemble_fragments(fragments)
        if len(stream) < 5:
            continue

        first_packet_number = min((f.packet_number for f in fragments), default=0)

        for handshake_body in iter_client_hello_messages(stream):
            info = extract_client_hello_info(handshake_body)
            if not info:
                continue
            if not info.offered_tls13:
                # JA4_d is defined for TLS 1.3 ClientHello messages.
                continue

            ech_status = ech_resolver.resolve(info.sni, info.has_ech, info.ech_config_id)
            ja4 = calculate_ja4(info)
            ja4_d = calculate_ja4d(info.supported_groups, info.key_share_groups, ech_status)
            full_ja4_ja4d = f"{ja4}_{ja4_d}"

            record = HandshakeRecord(
                packet_number=first_packet_number,
                src_ip=flow_key.src_ip,
                src_port=flow_key.src_port,
                dst_ip=flow_key.dst_ip,
                dst_port=flow_key.dst_port,
                sni=info.sni,
                supported_groups=info.supported_groups,
                key_share_groups=info.key_share_groups,
                has_ech=info.has_ech,
                ech_config_id=info.ech_config_id,
                offered_tls13=info.offered_tls13,
                ja4=ja4,
                ja4_d=ja4_d,
                full_ja4_ja4d=full_ja4_ja4d,
                ech_status=ech_status,
            )
            results.append(record)

            if verbose:
                groups_str = ", ".join(group_name(g) for g in info.supported_groups[:12]) or "-"
                keyshare_str = ", ".join(group_name(g) for g in info.key_share_groups) or "-"
                LOGGER.info(
                    "Packet=%s Flow=%s:%s -> %s:%s JA4_d=%s JA4+JA4_d=%s SNI=%s ECH=%s config_id=%s\n"
                    "  SupportedGroups=[%s]\n"
                    "  KeyShare=[%s]",
                    record.packet_number,
                    record.src_ip,
                    record.src_port,
                    record.dst_ip,
                    record.dst_port,
                    record.ja4_d,
                    record.full_ja4_ja4d,
                    record.sni,
                    "Yes" if record.has_ech else "No",
                    record.ech_config_id if record.ech_config_id is not None else "-",
                    groups_str,
                    keyshare_str,
                )

    return results


def print_summary(results: Sequence[HandshakeRecord]) -> None:
    print(f"\n{'=' * 78}")
    print("[*] Analysis Complete")
    print(f"[*] ClientHello packets found: {len(results)}")
    print(f"[*] Unique JA4 fingerprints: {len({r.ja4 for r in results})}")
    print(f"[*] Unique JA4_d fingerprints: {len({r.ja4_d for r in results})}")
    print(f"[*] Unique full JA4+JA4_d fingerprints: {len({r.full_ja4_ja4d for r in results})}")
    print(f"{'=' * 78}\n")

    summary: Dict[str, Dict[str, object]] = {}
    for r in results:
        bucket = summary.setdefault(
            r.ja4_d,
            {
                "count": 0,
                "snis": set(),
                "example_ja4": r.ja4,
                "example_full": r.full_ja4_ja4d,
                "example_groups": r.supported_groups[:12],
                "example_keyshare": r.key_share_groups,
            },
        )
        bucket["count"] = int(bucket["count"]) + 1
        cast_snis: Set[str] = bucket["snis"]  # type: ignore[assignment]
        cast_snis.add(r.sni)

    if not summary:
        print("No TLS 1.3 ClientHello packets were successfully parsed.")
        return

    print("JA4_d Fingerprints Summary:\n")
    for ja4_d, info in sorted(summary.items(), key=lambda item: int(item[1]["count"]), reverse=True):
        snis = sorted(list(info["snis"]))[:5]  # type: ignore[index]
        example_groups = info["example_groups"]  # type: ignore[assignment]
        example_keyshare = info["example_keyshare"]  # type: ignore[assignment]
        print(f"Fingerprint: {ja4_d}")
        print(f"  Count: {info['count']}")
        print(f"  SNIs: {', '.join(snis) if snis else '-'}")
        print(f"  Example JA4: {info['example_ja4']}")
        print(f"  Example JA4 + JA4_d: {info['example_full']}")
        print(f"  Example Groups: [{', '.join(group_name(g) for g in example_groups)}]")
        if example_keyshare:
            print(f"  Example Key Share: [{', '.join(group_name(g) for g in example_keyshare)}]")
        print()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze a PCAP and generate JA4_d fingerprints.")
    parser.add_argument("pcap_file", help="Path to the PCAP file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print per-handshake details")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument(
        "--dns-ech",
        action="store_true",
        help="Attempt best-effort ECH kem_id resolution via live DNS HTTPS lookups",
    )
    parser.add_argument(
        "--ech-map",
        help="Optional JSON file mapping hostname -> ECH status (n/c/h/q). Used before live DNS.",
    )
    parser.add_argument(
        "--dns-from-pcap",
        action="store_true",
        help="Extract hostname -> ECH status mappings from DNS HTTPS/SVCB answers present in the PCAP.",
    )
    parser.add_argument(
        "--dump-ech-map",
        help="Optional path to write the combined ECH map built from --dns-from-pcap and/or --ech-map.",
    )
    parser.add_argument(
        "--all-ports",
        action="store_true",
        help="Analyze all TCP destination ports instead of only 443/8443.",
    )
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="[%(levelname)s] %(message)s",
    )

    try:
        results = analyze_pcap(
            pcap_file=args.pcap_file,
            verbose=args.verbose,
            enable_dns=args.dns_ech,
            ech_map_file=args.ech_map,
            dns_from_pcap=args.dns_from_pcap,
            dump_ech_map_file=args.dump_ech_map,
            include_all_ports=args.all_ports,
        )
        print_summary(results)
        return 0
    except KeyboardInterrupt:
        LOGGER.error("Interrupted by user")
        return 130
    except Exception as exc:
        LOGGER.exception("Fatal error: %s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
