from scapy.all import rdpcap, IP, TCP, Raw
import dns.resolver, dns.rdatatype
HYBRID_GROUPS = [0x1D03D7, 0x1D03D8, 0x1D03D9]  # X25519MLKEM*, P256MLKEM*
PURE_PQ_GROUPS = [0xFEE1, 0xFEE2, 0xFEE3]  # ML-KEM-512/768/1024
def parse_client_hello(load):
    # TLS record: 16/17 03 03 <len3> ...
    tls_pos = load.find(b'\x16\x03\x01')  # TLS1.3 legacy
    if tls_pos == -1: tls_pos = load.find(b'\x16\x03\x03')
    if tls_pos == -1: return None
    rec_len = int.from_bytes(load[tls_pos+3:tls_pos+6], 'big')
    ch_start = tls_pos + 5  # Skip record hdr + handshake type/len
    if load[ch_start] != 1: return None  # CH type
    ch_len = int.from_bytes(load[ch_start+1:ch_start+4], 'big')
    ext_start = ch_start + 4 + 2 + load[ch_start+4] + 2  # Rough: vers + rand + legacy + ciphers
    sg_pos = load.find(b'\x00\x0a', ext_start, ext_start+500)
    if sg_pos == -1: return None
    list_len = int.from_bytes(load[sg_pos+2:sg_pos+4], 'big')
    groups_len = int.from_bytes(load[sg_pos+4:sg_pos+6], 'big')
    groups = []
    for i in range(0, groups_len, 2):
        if sg_pos+6+i+2 > len(load): break
        g = int.from_bytes(load[sg_pos+6+i:sg_pos+8+i], 'big')
        groups.append(g)
    key_shares = groups[:2]  # Stub
    sni = 'example.com'
    
    return groups, key_shares, sni


def get_ech_status(sni):
    try:
        answers = dns.resolver.resolve(sni, 'HTTPS')
        for rdata in answers:
            # Parse kemid stub
            return 'h' if '0031' in rdata.to_text() else 'n'
    except:
        return 'n'

pcap = rdpcap('Jose.pcap')
ch_count = 0
for pkt in pcap:
    if IP in pkt and TCP in pkt and pkt[TCP].dport == 443:
        load = bytes(pkt[TCP].payload)
        if TCP in pkt and pkt[TCP].dport == 443 and len(load) > 100:
            print(f"Pkt {pkt.time} len {len(load)} hex {load[:50].hex()}")
        load_len = len(load)
        print(f"443 pkt len {load_len} starts {load[:4].hex() if load_len > 0 else 'empty'}")
        if load_len > 200:
            ch1_pos = load.find(b'\x01', 5, 200)
            is_tls13 = load.startswith(b'\x16\x03\x03')
            print(f"  CH type pos: {ch1_pos}, TLS1.3? {is_tls13}")
        ch_count += 1
        if ch_count > 10: break
print(f"Checked {ch_count} 443 pkts")

print(f"Total packets: {len(pcap)}")
count_tcp_raw = 0
for pkt in pcap:
    if IP in pkt and TCP in pkt and pkt[TCP].dport == 443:
        load = bytes(pkt[TCP].payload)
        load_len = len(load)
        if 300 <= load_len <= 800 and load.startswith(b'\x16\x03\x03') and load.find(b'\x01', 5, 100) != -1:
            print(f"ClientHello found! Len: {load_len} Hex: {load[:40].hex()}")
            parsed = parse_client_hello(load)
            if parsed:
                groups, shares, sni = parsed
                ech = get_ech_status(sni)
                h_count = min(sum(g in HYBRID_GROUPS for g in groups), 9) or 0
                p_count = min(sum(g in PURE_PQ_GROUPS for g in groups), 9) or 0
                behavior = 'o' if any(ks in groups for ks in shares) else 'p'
                ja4d = f"{h_count}-{p_count}-{behavior}-{ech}"
                print(f"JA4d: {ja4d} | Groups: {[hex(g) for g in groups[:8]]} | SNI: {sni}")
                break
            if not parsed:
                tls_pos = load.find(b'\x16\x03\x01')
                ch_type = load[5] if len(load)>5 else ord('s')
                print(f"  Parse fail: tls_pos={tls_pos}, ch_type={ch_type}")
            else:
                print("Parse failed")
    if count_tcp_raw >= 3: break  # Limit output

