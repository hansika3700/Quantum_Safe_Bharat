#!/usr/bin/env python3
"""
Quantum Safe Bharat - passive post-quantum readiness scanner.

For each domain it opens ONE normal HTTPS handshake (the same thing a browser
does when you visit the site) and records only what the server publicly offers:
  - TLS version (TLS 1.3 is required before quantum-safe key exchange can be added)
  - cipher suite
  - certificate public-key type and size (RSA / ECDSA are quantum-vulnerable)
  - certificate expiry
  - whether the server accepts the hybrid post-quantum key exchange
    X25519MLKEM768 (needs OpenSSL 3.5+ on your PC; skipped otherwise)

No vulnerability probing, no login attempts, no crawling.

Usage:
    python qsb_scan.py domains.txt
    python qsb_scan.py domains.txt --out results.csv --openssl "C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe"
"""

import argparse
import csv
import datetime as dt
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time

PQ_GROUP = "X25519MLKEM768"
TIMEOUT = 10


def load_domains(path):
    domains = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            line = re.sub(r"^https?://", "", line).split("/", 1)[0]
            if line and line not in domains:
                domains.append(line)
    return domains


def cert_key_info(der_cert):
    """Return (key_type, key_bits, not_after) using the 'cryptography' package."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa
    except ImportError:
        return ("unknown (pip install cryptography)", "", "")
    cert = x509.load_der_x509_certificate(der_cert)
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        ktype, bits = "RSA", pub.key_size
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        ktype, bits = f"ECDSA-{pub.curve.name}", pub.key_size
    elif isinstance(pub, ed25519.Ed25519PublicKey):
        ktype, bits = "Ed25519", 256
    elif isinstance(pub, ed448.Ed448PublicKey):
        ktype, bits = "Ed448", 448
    elif isinstance(pub, dsa.DSAPublicKey):
        ktype, bits = "DSA", pub.key_size
    else:
        ktype, bits = type(pub).__name__, ""
    try:
        not_after = cert.not_valid_after_utc.date().isoformat()
    except AttributeError:
        not_after = cert.not_valid_after.date().isoformat()
    return (ktype, bits, not_after)


def tls_handshake(domain):
    ctx = ssl.create_default_context()
    # We only read public configuration, so accept certificates even if the
    # chain is broken; record whether it validated separately.
    result = {"cert_valid": "yes"}
    for verify in (True, False):
        if not verify:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    result["tls_version"] = ssock.version()
                    result["cipher"] = ssock.cipher()[0]
                    der = ssock.getpeercert(binary_form=True)
                    k, b, exp = cert_key_info(der)
                    result.update(cert_key=k, key_bits=b, cert_expiry=exp)
                    return result
        except ssl.SSLCertVerificationError:
            result["cert_valid"] = "no"
            continue
    raise RuntimeError("handshake failed")


def find_pq_openssl(explicit):
    """Return path to an openssl binary that supports ML-KEM, or None."""
    candidates = [explicit] if explicit else [shutil.which("openssl")]
    for path in candidates:
        if not path:
            continue
        try:
            out = subprocess.run([path, "version"], capture_output=True, text=True, timeout=5).stdout
            m = re.search(r"OpenSSL (\d+)\.(\d+)", out)
            if m and (int(m.group(1)), int(m.group(2))) >= (3, 5):
                return path
        except Exception:
            pass
    return None


def pq_hybrid_supported(openssl, domain):
    """Offer ONLY the hybrid PQ group; success means the server supports it."""
    try:
        p = subprocess.run(
            [openssl, "s_client", "-connect", f"{domain}:443", "-servername", domain,
             "-groups", PQ_GROUP, "-tls1_3", "-brief"],
            input="", capture_output=True, text=True, timeout=TIMEOUT + 5,
        )
        text = p.stdout + p.stderr
        if re.search(r"(Negotiated TLS1\.3 group|Server Temp Key|Peer Temp Key).*MLKEM", text, re.I) \
                or ("CONNECTION ESTABLISHED" in text and p.returncode == 0):
            return "yes"
        return "no"
    except Exception:
        return "error"


def readiness(row):
    """Simple 0-100 score for the dashboard / report."""
    if row["status"] != "ok":
        return ""
    score = 0
    if row["tls_version"] == "TLSv1.3":
        score += 40
    if row["pq_hybrid_kex"] == "yes":
        score += 50
    if row["cert_valid"] == "yes":
        score += 10
    return score


def main():
    ap = argparse.ArgumentParser(description="Passive post-quantum readiness scanner")
    ap.add_argument("domains", help="text file, one domain per line")
    ap.add_argument("--out", default="qsb_results.csv")
    ap.add_argument("--openssl", help="path to OpenSSL 3.5+ binary for the PQ key-exchange test")
    ap.add_argument("--delay", type=float, default=1.0, help="seconds between sites (be polite)")
    args = ap.parse_args()

    domains = load_domains(args.domains)
    openssl = find_pq_openssl(args.openssl)
    print(f"Scanning {len(domains)} domains")
    print(f"Python ssl: {ssl.OPENSSL_VERSION}")
    print("PQ key-exchange test:", f"ON ({openssl})" if openssl else "OFF (needs OpenSSL 3.5+, see README)")
    print()

    fields = ["domain", "status", "tls_version", "cipher", "cert_key", "key_bits",
              "cert_expiry", "cert_valid", "pq_hybrid_kex", "readiness_score", "error"]
    rows = []
    for i, d in enumerate(domains, 1):
        row = {k: "" for k in fields}
        row["domain"] = d
        try:
            row.update(tls_handshake(d))
            row["status"] = "ok"
            row["pq_hybrid_kex"] = pq_hybrid_supported(openssl, d) if openssl else "not tested"
        except Exception as e:
            row["status"] = "unreachable"
            row["error"] = (str(e) or type(e).__name__)[:120]
        row["readiness_score"] = readiness(row)
        rows.append(row)
        print(f"[{i:>3}/{len(domains)}] {d:<35} {row['status']:<12} "
              f"{row['tls_version']:<8} {row['cert_key']:<18} PQ:{row['pq_hybrid_kex']}")
        time.sleep(args.delay)

    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

    ok = [r for r in rows if r["status"] == "ok"]
    n = len(ok)
    print("\n================ SUMMARY (use these in the form) ================")
    print(f"Domains attempted : {len(rows)}")
    print(f"N  (reached)      : {n}")
    if n:
        vuln_cert = sum(1 for r in ok if r["cert_key"].startswith(("RSA", "ECDSA", "DSA", "Ed")))
        no_tls13 = sum(1 for r in ok if r["tls_version"] != "TLSv1.3")
        print(f"Quantum-vulnerable certificates (RSA/ECC)     : {vuln_cert}/{n} = {100*vuln_cert/n:.0f}%")
        print(f"Y  No TLS 1.3 (cannot add PQ without upgrade) : {no_tls13}/{n} = {100*no_tls13/n:.0f}%")
        tested = [r for r in ok if r["pq_hybrid_kex"] in ("yes", "no")]
        if tested:
            no_pq = sum(1 for r in tested if r["pq_hybrid_kex"] == "no")
            print(f"X  No PQ-hybrid key exchange                  : {no_pq}/{len(tested)} = {100*no_pq/len(tested):.0f}%")
        else:
            print("X  No PQ-hybrid key exchange                  : not measured (install OpenSSL 3.5+)")
        avg = sum(r["readiness_score"] for r in ok) / n
        print(f"Average readiness score (0-100)               : {avg:.0f}")
    print(f"\nFull results saved to {args.out}")


if __name__ == "__main__":
    sys.exit(main())
