from scapy.all import rdpcap, TCP, Raw
pcap = rdpcap('tls13.pcap')
hybrid_groups = [0x1D03D7, 0x1D03D8]  # Hybrid from drafts
pure_pq_groups = [0xFEE1, 0xFEE2]  # ML-KEM
for pkt in pcap:
    load = bytes(pkt[Raw]) if Raw in pkt else b''
    i = load.find(b'\x01\x00')  # CH type + len
    if i != -1:
        print("ClientHello found")
        # Find ext list end (after ALPN/compress)
        ext_start = i + 5 + int.from_bytes(load[i+5:i+8], 'big') + 2  # Rough
        sg_type = load.find(b'\x00\x0a', ext_start)
        if sg_type != -1:
            sg_len = int.from_bytes(load[sg_type+2:sg_type+4], 'big')
            groups_len = int.from_bytes(load[sg_type+4:sg_type+6], 'big')
            groups = [int.from_bytes(load[sg_type+6+j:sg_type+8+j], 'big') for j in range(0, groups_len, 2)]
            print("Supported groups:", [hex(g) for g in groups])
            print("Hybrid count:", sum(g in hybrid_groups for g in groups))
            print("Pure PQ count:", sum(g in pure_pq_groups for g in groups))
        break
