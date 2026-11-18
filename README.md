# Quantum Safe Bharat

**A passive post-quantum readiness scanner for India's digital public infrastructure.**

Quantum computers running Shor's algorithm will break the RSA and elliptic-curve cryptography that protects today's websites. Attackers can already record encrypted traffic and decrypt it later ("harvest now, decrypt later"). Quantum Safe Bharat checks whether public portals already support quantum-safe key exchange, scores their readiness, and supports plain-language migration planning aligned with NIST's post-quantum standards and India's DST quantum-safe roadmap.

Developed for the **Seva First Innovation Challenge 2026** (Delhi Technological University).

---

## What it checks

For each portal, the scanner makes two ordinary TLS handshakes on port 443:

1. **Standard handshake** – records the TLS version, cipher suite, and certificate key type, size, expiry and validity.
2. **Quantum-safe test** – offers *only* the hybrid key-exchange group `X25519MLKEM768` (X25519 + ML-KEM-768, NIST FIPS 203). If the server completes the handshake, it supports quantum-safe key exchange.

Each portal gets a readiness score from 0 to 100:

| Check | Points |
|---|---|
| Uses TLS 1.3 | 40 |
| Accepts quantum-safe hybrid key exchange | 50 |
| Valid certificate | 10 |

## Files

| File | Purpose |
|---|---|
| `qsb_scan.py` | The scanner. Writes one row per portal to a CSV file |
| `qsb_analyze.py` | Turns scan results into headline numbers, sector tables and charts |
| `qsb_demo.py` | A short, self-captioned live demonstration on six portals |
| `domains.txt` | Starter list of public Indian portals, grouped by sector |

## Requirements

- Python 3.10+
- **OpenSSL 3.5 or newer** for the quantum-safe test (on Windows, e.g. Shining Light "Win64 OpenSSL Light")
- Python packages: `pip install -r requirements.txt`

Without OpenSSL 3.5+, the scanner still records TLS versions and certificates, but marks the quantum-safe test as "not tested".

## Usage

```bash
pip install -r requirements.txt

# Scan (add --openssl with your OpenSSL 3.5+ path to enable the quantum-safe test)
python qsb_scan.py domains.txt --openssl "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" --out results.csv

# Analyse results into numbers and charts (saved in slide_outputs/)
python qsb_analyze.py results.csv domains.txt

# Live demonstration
python qsb_demo.py
```

Some government portals block connections from outside India, so scan from an Indian network for full coverage.

## Responsible use

- The scanner is **passive**. It reads only the encryption settings that any web browser sees when it visits a site. It does not probe for vulnerabilities, attempt logins or crawl pages.
- Scans are rate-limited (one portal per second by default). Please keep this delay.
- Only scan public websites, or systems you are authorised to assess.
- Scan results naming specific organisations are **not** published in this repository. Findings should be shared with the organisations concerned or with CERT-In, not posted publicly.

## Limitations

- Assesses public HTTPS endpoints only. Email servers, APIs, VPNs and internal systems are out of scope.
- For portals behind a CDN, results reflect the CDN edge, not necessarily the origin server.
- Currently tests the `X25519MLKEM768` group only. Further ML-KEM groups are planned.
- Certificate validity depends on the local system's trust store.

## Roadmap

- Sector dashboard (Streamlit)
- AI-generated, plain-language migration reports for each organisation
- Expanded scanning of 200+ portals from within India
- Additional quantum-safe groups (e.g. ML-KEM-1024) and certificate checks (ML-DSA)

## References

- NIST FIPS 203, 204, 205 – Post-quantum cryptography standards (2024)
- NIST IR 8547 – Transition to Post-Quantum Cryptography Standards
- DST / National Quantum Mission – *Implementation of Quantum Safe Ecosystem in India: Report of the Task Force* (2026)

## Author

Hansika Mittal – Ph.D. Scholar, Delhi Technological University

## License

Apache License 2.0
