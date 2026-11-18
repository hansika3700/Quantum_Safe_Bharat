#!/usr/bin/env python3
"""
Quantum Safe Bharat - live demo for the video (runs on its own, no key presses).

Put this file in the same folder as qsb_scan.py and run:
    python qsb_demo.py

It shows short captions, scans 6 well-known Indian portals live (with a
timestamp, so viewers can see it is a real, current scan), then prints the
full results of the 16 Nov 2026 scan. Do the Chrome check by hand afterwards.

Make it slower or faster:  python qsb_demo.py --speed 1.5   (1.5x longer pauses)
"""

import argparse
import datetime as dt
import os
import sys
import time

try:
    import qsb_scan
except ImportError:
    print("qsb_scan.py must be in the same folder as this file.")
    sys.exit(1)

OPENSSL = r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe"

DEMO_PORTALS = [
    ("rbi.org.in", "Reserve Bank of India"),
    ("npci.org.in", "NPCI (UPI payments)"),
    ("hdfcbank.com", "HDFC Bank"),
    ("uidai.gov.in", "Aadhaar (UIDAI)"),
    ("digilocker.gov.in", "DigiLocker"),
    ("sbi.co.in", "State Bank of India"),
]

B, G, R, Y, C, D, X = "\033[1m", "\033[92m", "\033[91m", "\033[93m", "\033[96m", "\033[2m", "\033[0m"
if os.name == "nt":
    os.system("")  # enable colours in the Windows terminal

SPEED = 1.0


def pause(seconds):
    time.sleep(seconds * SPEED)


def caption(title, lines, line_pause=0.7):
    print()
    print(C + B + "=" * 72 + X)
    print(C + B + "  " + title + X)
    print(C + B + "=" * 72 + X)
    for line in lines:
        print("  " + line)
        pause(line_pause)


def main():
    global SPEED
    ap = argparse.ArgumentParser()
    ap.add_argument("--speed", type=float, default=1.0, help="multiply all pauses (e.g. 1.5 = slower)")
    args = ap.parse_args()
    SPEED = args.speed

    os.system("cls" if os.name == "nt" else "clear")
    caption("QUANTUM SAFE BHARAT  -  LIVE PROTOTYPE DEMONSTRATION", [
        "Is India's digital public infrastructure ready for quantum computers?",
        "",
        "This prototype checks Indian public websites for quantum-safe encryption.",
        "It is fully passive: it reads only what every web browser already sees.",
        "No hacking, no probing, no logins.",
    ])
    pause(3)

    openssl = qsb_scan.find_pq_openssl(OPENSSL)
    caption("HOW EACH WEBSITE IS TESTED", [
        "Test 1: connect like a normal browser and record the encryption settings.",
        "Test 2: offer ONLY the new quantum-safe method (hybrid ML-KEM, NIST FIPS 203).",
        "        Website accepts -> QUANTUM-SAFE.   Website refuses -> NOT QUANTUM-SAFE.",
        "",
        "Quantum-safe test engine: " + (G + "ON" + X if openssl else Y + "OFF (OpenSSL 3.5+ not found)" + X),
    ])
    pause(3)

    now = dt.datetime.now().strftime("%d %b %Y, %H:%M:%S")
    caption("LIVE SCAN OF 6 INDIAN PORTALS", [f"Scan started: {now}"], line_pause=0.5)
    print()
    print(B + f"  {'Portal':<26}{'Website':<20}{'Protocol':<10}{'Certificate':<17}Quantum-safe?" + X)
    print("  " + "-" * 90)
    safe = vuln = 0
    for domain, name in DEMO_PORTALS:
        print(D + f"  testing {domain} ..." + X, end="\r", flush=True)
        try:
            info = qsb_scan.tls_handshake(domain)
            pq = qsb_scan.pq_hybrid_supported(openssl, domain) if openssl else "not tested"
            if pq == "yes":
                verdict, safe = G + B + "YES - protected" + X, safe + 1
            elif pq == "no":
                verdict, vuln = R + B + "NO  - vulnerable" + X, vuln + 1
            else:
                verdict = Y + pq + X
            cert = f"{info.get('cert_key', '')} {info.get('key_bits', '')}".strip()
            line = f"  {name:<26}{domain:<20}{info.get('tls_version', ''):<10}{cert:<17}{verdict}"
        except Exception:
            line = f"  {name:<26}{domain:<20}" + Y + "unreachable from this network" + X
        print(" " * 60, end="\r")
        print(line)
        pause(0.6)
    done = dt.datetime.now().strftime("%H:%M:%S")
    print()
    print(f"  Scan finished: {done}   |   {G}{safe} quantum-safe{X}   |   {R}{vuln} vulnerable{X}")
    pause(1.5)
    print()
    print("  " + B + "What this shows:" + X + " some Indian institutions already use quantum-safe")
    print("  encryption, while key citizen services do not. The fix exists today.")
    pause(6)

    caption("FULL RESULTS: 60 INDIAN PUBLIC PORTALS SCANNED ON 16 NOV 2026", [
        "41 portals responded.",
        R + B + "68%" + X + " of those tested offer NO quantum-safe key exchange (25 of 37).",
        R + B + "100%" + X + " use quantum-vulnerable RSA/ECC certificates.",
        R + B + "10%" + X + " have not yet adopted TLS 1.3, the prerequisite for quantum-safe encryption.",
        "Government & public services: only " + R + B + "21%" + X + " quantum-safe,"
        " vs " + G + B + "75%" + X + " of financial regulators.",
    ], line_pause=1.2)
    pause(5)

    caption("NEXT: INDEPENDENT VERIFICATION IN GOOGLE CHROME", [
        "Chrome shows the key exchange each website uses (F12 -> Security tab):",
        "  X25519MLKEM768  = quantum-safe",
        "  X25519          = not quantum-safe",
    ], line_pause=1.0)
    print()


if __name__ == "__main__":
    main()
