#!/usr/bin/env python3
"""
Quantum Safe Bharat - turn scan results into slide-ready numbers and charts.

Run AFTER qsb_scan.py:
    python qsb_analyze.py qsb_results.csv domains.txt

Creates a folder "slide_outputs" with:
    slide_numbers.txt          - every number for the deck, with ready-to-paste sentences
    sector_table.csv           - per-sector breakdown (paste into a PPT table)
    chart_sector_readiness.png - average readiness score by sector (slide 4 / 9)
    chart_key_findings.png     - headline percentages (slide 4 / 9)
    chart_cert_types.png       - certificate key types found (slide 9 / 18)
    sample_rows.csv            - 5 example rows for the "sample results" table (slide 18)

Needs: pip install matplotlib
"""

import csv
import os
import re
import sys
from collections import Counter, defaultdict

INK = "#0b0b0b"
INK2 = "#52514e"
BAR = "#2a78d6"
GRID = "#e4e3df"
BG = "#ffffff"
PQ_ALGOS = ("RSA", "ECDSA", "DSA", "Ed")


def load_sectors(domains_path):
    """Map domain -> sector using the '# --- Sector ---' headings in domains.txt."""
    sectors, current = {}, "Other"
    with open(domains_path, encoding="utf-8") as f:
        for line in f:
            m = re.match(r"^\s*#\s*-+\s*(.+?)\s*-+\s*$", line)
            if m:
                current = m.group(1).replace("&", "and")
                continue
            d = line.split("#", 1)[0].strip()
            d = re.sub(r"^https?://", "", d).split("/", 1)[0]
            if d:
                sectors[d] = current
    return sectors


def pct(a, b):
    return 100.0 * a / b if b else 0.0


def short_sector(name):
    name = re.sub(r"\(.*?\)", "", name).strip()
    return {
        "Central government and digital public infrastructure": "Central govt & DPI",
        "State portals": "State govt (North)",
        "Regulators and financial infrastructure": "Regulators & finance",
        "Public-sector banks": "Public-sector banks",
        "Private banks": "Private banks",
        "Other public services": "Other public services",
    }.get(name, name)


def style_axes(ax):
    ax.set_facecolor(BG)
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)
    ax.spines["bottom"].set_color(GRID)
    ax.tick_params(colors=INK2, labelsize=10, length=0)
    ax.xaxis.grid(True, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def hbar(path, labels, values, title, subtitle, xlabel, xmax=None, fmt="{:.0f}"):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.patches import FancyBboxPatch

    h = 1.1 + 0.55 * len(labels)
    fig, ax = plt.subplots(figsize=(9, h), dpi=200)
    fig.patch.set_facecolor(BG)
    style_axes(ax)
    y = list(range(len(labels)))[::-1]
    top = xmax or (max(values) * 1.15 if values and max(values) > 0 else 1)
    ax.set_xlim(0, top)
    ax.set_ylim(-0.6, len(labels) - 0.4)
    for yi, v in zip(y, values):
        if v > 0:
            ax.add_patch(FancyBboxPatch((0, yi - 0.28), v, 0.56,
                                        boxstyle="round,pad=0,rounding_size=0.08",
                                        mutation_aspect=top / len(labels) / 4,
                                        linewidth=0, facecolor=BAR))
        ax.text(v + top * 0.012, yi, fmt.format(v), va="center", ha="left",
                fontsize=10.5, color=INK, fontweight="bold")
    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=10.5, color=INK)
    ax.set_xlabel(xlabel, color=INK2, fontsize=9.5)
    fig.text(0.01, 0.985, title, ha="left", va="top", fontsize=13.5, color=INK, fontweight="bold")
    fig.text(0.01, 0.985 - 0.30 / h, subtitle, ha="left", va="top", fontsize=9.5, color=INK2)
    fig.tight_layout(rect=(0, 0, 1, 1 - 0.62 / h))
    fig.savefig(path, facecolor=BG)
    plt.close(fig)


def main():
    if len(sys.argv) < 3:
        print("Usage: python qsb_analyze.py qsb_results.csv domains.txt")
        return 1
    results_path, domains_path = sys.argv[1], sys.argv[2]
    out = "slide_outputs"
    os.makedirs(out, exist_ok=True)

    sectors = load_sectors(domains_path)
    with open(results_path, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        r["sector"] = short_sector(sectors.get(r["domain"], "Other"))

    ok = [r for r in rows if r["status"] == "ok"]
    n_all, n = len(rows), len(ok)
    if not n:
        print("No reachable sites in the results - nothing to analyse.")
        return 1

    no_tls13 = sum(r["tls_version"] != "TLSv1.3" for r in ok)
    vuln_cert = sum(r["cert_key"].startswith(PQ_ALGOS) for r in ok)
    tested = [r for r in ok if r["pq_hybrid_kex"] in ("yes", "no")]
    no_pq = sum(r["pq_hybrid_kex"] == "no" for r in tested)
    pq_yes = sum(r["pq_hybrid_kex"] == "yes" for r in tested)
    bad_cert = sum(r["cert_valid"] == "no" for r in ok)
    scores = [float(r["readiness_score"]) for r in ok if r["readiness_score"] != ""]
    avg = sum(scores) / len(scores) if scores else 0
    certs = Counter(re.sub(r"-.*", "", r["cert_key"]) or "unknown" for r in ok)
    rsa_sizes = Counter(r["key_bits"] for r in ok if r["cert_key"] == "RSA")

    # ---- per-sector table ----
    by = defaultdict(list)
    for r in ok:
        by[r["sector"]].append(r)
    table = []
    for s, rs in by.items():
        t = [r for r in rs if r["pq_hybrid_kex"] in ("yes", "no")]
        sc = [float(r["readiness_score"]) for r in rs if r["readiness_score"] != ""]
        table.append({
            "sector": s,
            "portals_reached": len(rs),
            "pct_no_tls13": round(pct(sum(r["tls_version"] != "TLSv1.3" for r in rs), len(rs))),
            "pct_rsa_ecc_cert": round(pct(sum(r["cert_key"].startswith(PQ_ALGOS) for r in rs), len(rs))),
            "pct_no_pq_kex": round(pct(sum(r["pq_hybrid_kex"] == "no" for r in t), len(t))) if t else "not tested",
            "avg_readiness_0_100": round(sum(sc) / len(sc)) if sc else "",
        })
    table.sort(key=lambda d: d["avg_readiness_0_100"] if d["avg_readiness_0_100"] != "" else -1)
    with open(os.path.join(out, "sector_table.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(table[0].keys()))
        w.writeheader()
        w.writerows(table)

    # ---- sample rows ----
    cols = ["domain", "sector", "tls_version", "cert_key", "key_bits", "pq_hybrid_kex", "readiness_score"]
    with open(os.path.join(out, "sample_rows.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(cols)
        seen = set()
        for r in sorted(ok, key=lambda r: float(r["readiness_score"] or 0)):
            if r["sector"] not in seen and len(seen) < 5:
                seen.add(r["sector"])
                w.writerow([r[c] for c in cols])

    # ---- charts ----
    charts_ok = True
    try:
        hbar(os.path.join(out, "chart_sector_readiness.png"),
             [d["sector"] for d in table], [d["avg_readiness_0_100"] or 0 for d in table],
             "Post-quantum readiness of Indian public portals, by sector",
             f"Average readiness score (0-100) across {n} portals - passive scan",
             "Readiness score (higher is better)", xmax=100)
        labels, vals = ["Use RSA/ECC certificates (quantum-vulnerable)", "Not on TLS 1.3 (cannot add PQ yet)"], [pct(vuln_cert, n), pct(no_tls13, n)]
        if tested:
            labels.insert(0, "No quantum-safe key exchange")
            vals.insert(0, pct(no_pq, len(tested)))
        hbar(os.path.join(out, "chart_key_findings.png"), labels, vals,
             "Key findings", f"Share of {n} reachable Indian public portals", "% of portals",
             xmax=100, fmt="{:.0f}%")
        cl = [k for k, _ in certs.most_common()]
        hbar(os.path.join(out, "chart_cert_types.png"), cl, [certs[k] for k in cl],
             "Certificate key types found", f"Number of portals ({n} reachable)", "Portals")
    except ImportError:
        charts_ok = False

    # ---- slide numbers ----
    L = []
    L.append("QUANTUM SAFE BHARAT - NUMBERS FOR THE DECK")
    L.append("=" * 60)
    L.append(f"Portals in list (attempted) : {n_all}")
    L.append(f"N  Portals reached           : {n}")
    L.append(f"   Unreachable (excluded)    : {n_all - n}")
    if tested:
        L.append(f"X  No quantum-safe key exchange : {no_pq}/{len(tested)} = {pct(no_pq, len(tested)):.0f}%")
        L.append(f"   Already quantum-safe (hybrid ML-KEM) : {pq_yes}/{len(tested)} = {pct(pq_yes, len(tested)):.0f}%")
    else:
        L.append("X  No quantum-safe key exchange : NOT MEASURED (needs OpenSSL 3.5+)")
    L.append(f"Y  Not on TLS 1.3            : {no_tls13}/{n} = {pct(no_tls13, n):.0f}%")
    L.append(f"Z  RSA/ECC certificates      : {vuln_cert}/{n} = {pct(vuln_cert, n):.0f}%")
    L.append(f"   Invalid/untrusted certs   : {bad_cert}/{n} = {pct(bad_cert, n):.0f}%")
    L.append(f"   Average readiness (0-100) : {avg:.0f}")
    L.append("   Certificate types         : " + ", ".join(f"{k} {v}" for k, v in certs.most_common()))
    if rsa_sizes:
        L.append("   RSA key sizes             : " + ", ".join(f"{k}-bit x{v}" for k, v in sorted(rsa_sizes.items())))
    L.append("")
    L.append("PER SECTOR (lowest readiness first)")
    for d in table:
        L.append(f"  {d['sector']:<24} n={d['portals_reached']:<3} no TLS1.3 {d['pct_no_tls13']}%  "
                 f"RSA/ECC {d['pct_rsa_ecc_cert']}%  no PQ {d['pct_no_pq_kex']}{'%' if tested else ''}  "
                 f"score {d['avg_readiness_0_100']}")
    L.append("")
    L.append("READY-TO-PASTE SENTENCES")
    L.append("-" * 60)
    if tested:
        L.append(f"Our passive assessment of {n} public Indian government, health, education and banking "
                 f"portals found that {pct(no_pq, len(tested)):.0f}% offer no quantum-safe (hybrid ML-KEM) key "
                 f"exchange and {pct(no_tls13, n):.0f}% have not yet adopted TLS 1.3, the prerequisite for "
                 f"quantum-safe cryptography.")
    else:
        L.append(f"Our passive assessment of {n} public Indian government, health, education and banking "
                 f"portals found that {pct(no_tls13, n):.0f}% have not yet adopted TLS 1.3, the prerequisite for "
                 f"quantum-safe cryptography, and {pct(vuln_cert, n):.0f}% rely on quantum-vulnerable RSA or "
                 f"elliptic-curve certificates.")
    if table and table[0]["avg_readiness_0_100"] != "":
        L.append(f"The least prepared sector was {table[0]['sector']} (average readiness "
                 f"{table[0]['avg_readiness_0_100']}/100); the most prepared was {table[-1]['sector']} "
                 f"({table[-1]['avg_readiness_0_100']}/100).")
    L.append(f"Average post-quantum readiness across all portals: {avg:.0f} out of 100.")
    L.append("")
    L.append("Method note for the slide: passive scan of publicly offered TLS configuration only; "
             "no vulnerability probing. Scan date: [add date]. Scan location: [Qatar / India].")
    text = "\n".join(L)
    with open(os.path.join(out, "slide_numbers.txt"), "w", encoding="utf-8") as f:
        f.write(text + "\n")
    print(text)
    print(f"\nSaved to folder: {out}/")
    if not charts_ok:
        print("Charts skipped - run: pip install matplotlib   then run this script again.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
