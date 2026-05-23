#!/usr/bin/env python3
from scapy.all import rdpcap  # pip3 install --user scapy
HYBRID_GROUPS = [0x1D03D7, 0x1D03D8, 0x1D03D9]
PURE_PQ_GROUPS = [0xFEE1, 0xFEE2, 0xFEE3]
def fingerprint(pcap_file):
    # Regex CH → groups → h-p-b-e
    # + DNS ECH rdata
    return "1-0-o-n"  # stub
if __name__ == "__main__":
    print(fingerprint("tls13.pcap"))
