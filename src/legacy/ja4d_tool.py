from scapy.all import rdpcap, TCP, Raw
import dns.resolver
def generate_ja4d(supported_groups, key_shares, ech_status='n'):
    hybrid = min(len([g for g in supported_groups if g in [0x1D03D7]]),9) or '0'
    pure = min(len([g for g in supported_groups if g in [0xFEE1]]),9) or '0'
    behavior = 'o' if set(key_shares) & set(supported_groups) else 'p'
    return f"{hybrid}-{pure}-{behavior}-{ech_status}"

# Stub parser (expand later)
def parse_ch(pkt):
    # Synthetic for now
    return [0x001d], [0x001d], None

for pkt in rdpcap('tls13.pcap'):
    if TCP in pkt and Raw in pkt:
        groups, shares, kem = parse_ch(pkt)
        ja4d = generate_ja4d(groups, shares)
        print("JA4d:", ja4d)
