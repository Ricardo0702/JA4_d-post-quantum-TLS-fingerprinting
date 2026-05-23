# JA4_d-post-quantum-TLS-fingerprinting

JA4_d is a post-quantum-aware extension to the JA4 TLS fingerprinting methodology for identifying PQ cryptographic behavior in TLS 1.3 ClientHello messages. 

This repository contains the implementation, synthetic datasets, example outputs, and supporting material developed for the Bachelor’s Thesis project:

> **“Post-quantum-aware TLS client fingerprinting: JA4_d”**

The project focuses on passive TLS traffic analysis and visibility into post-quantum deployment scenarios, including:
- Hybrid post-quantum key exchange
- Pure post-quantum negotiation
- Mixed PQ behavior
- Encrypted ClientHello (ECH)-aware classification
- Passive fingerprint generation from offline PCAP captures

---

# Repository Structure

```text
src/
    Main JA4_d implementation

src/legacy/
    Early prototypes and development versions

generators/
    Synthetic TLS traffic generation scripts

datasets/
    Synthetic datasets and sample captures

outputs/
    Example analyzer outputs

docs/
    Thesis document and supporting documentation
```

---

# Features

- TLS 1.3 ClientHello parsing
- GREASE-aware extension handling
- Hybrid and pure PQ NamedGroup detection
- JA4_d fingerprint generation
- ECH-aware classification support
- Basic TCP stream reassembly
- Synthetic dataset generation
- Validation using offline PCAP captures
- Support for current and legacy PQ code points

---

# JA4_d Fingerprint Format

The JA4_d fingerprint format follows:

```text
hybrid_count - purepq_count - behavior - ech_status
```

Example:

```text
1-0-o-n
```

Where:
- `1` → one hybrid PQ group observed
- `0` → zero pure PQ groups observed
- `o` → optimistic behavior
- `n` → no ECH-related PQ classification detected

Behavior values:
- `o` → optimistic
- `p` → pessimistic
- `m` → mixed

ECH status values:
- `n` → no ECH classification
- `c` → classical ECH
- `h` → hybrid PQ ECH
- `q` → pure PQ ECH

---

# Installation

Clone the repository:

```bash
git clone https://github.com/Ricardo0702/JA4_d-post-quantum-TLS-fingerprinting.git
cd JA4_d-post-quantum-TLS-fingerprinting
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

# Requirements

Main dependencies:
- scapy
- dnspython
- rich

Python 3.10+ recommended.

---

# Usage Examples

Basic analysis:

```bash
python3 src/JA4_d_v3.py datasets/synthetic/ja4d_test_traffic.pcap
```

ECH-aware analysis:

```bash
python3 src/JA4_d_v3.py datasets/synthetic/ja4d_test_traffic.pcap --ech-map datasets/synthetic/ja4d_ech_map.json
```

Verbose mode:

```bash
python3 src/JA4_d_v3.py datasets/synthetic/ja4d_test_traffic.pcap -v
```

---

# Synthetic Dataset

The repository includes synthetic TLS datasets designed to validate:
- Classical TLS behavior
- Hybrid PQ negotiation
- Pure PQ negotiation
- Mixed PQ behavior
- ECH-aware PQ scenarios
- Fragmented ClientHello handling
- Legacy and draft PQ code points

The synthetic traffic generator is available in:

```text
generators/Synthetic_traffic_v2.py
```

---

# Notes on Real Traffic Captures

Real traffic captures used during evaluation are not publicly distributed for privacy reasons.

Only synthetic and non-sensitive example datasets are included in this repository.

---

# Thesis Context

This repository accompanies the Bachelor’s Thesis:

> **Post-quantum-aware TLS client fingerprinting: JA4_d**

The work explores the feasibility of extending passive TLS fingerprinting methodologies to improve visibility into emerging post-quantum cryptographic deployment strategies.

---

# Limitations

Current limitations include:
- Focus on TLS-over-TCP traffic
- No QUIC/HTTP3 support
- Limited live DNS ECH visibility
- Experimental handling of legacy PQ identifiers
- Offline PCAP-oriented workflow

---

# License

This project is released under the MIT License.

---

# Author

Ricardo Pereira González – Bachelor’s Thesis Project – Cybersecurity / Network Analysis – Telecommunications Network Engineering Degree (Course 2025 - 2026)
