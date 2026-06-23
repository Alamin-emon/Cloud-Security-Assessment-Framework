#!/usr/bin/env python3
"""
Comparative Analysis Engine
============================
Reads Prowler and ZeusCloud output (real or mock) and produces:
  - Console summary report
  - results/comparison_table.csv
  - results/metrics_summary.json
  - results/chart_severity.png
  - results/chart_coverage.png
  - results/chart_attack_paths.png
  - results/chart_radar.png

Usage:
  pip install matplotlib numpy pandas
  python analyze.py
"""

import json, csv, os, textwrap
from pathlib import Path
from collections import Counter, defaultdict

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import numpy as np
    PLOTTING = True
except ImportError:
    print("[WARN] matplotlib not installed — skipping charts. pip install matplotlib numpy")
    PLOTTING = False

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE        = Path(__file__).parent.parent
RESULTS_DIR = BASE / "results"
PROWLER_F   = RESULTS_DIR / "prowler_output.json"
ZEUS_F      = RESULTS_DIR / "zeuscloud_output.json"

# ── Colors ────────────────────────────────────────────────────────────────────
SEV_COLORS = {
    "Critical": "#C62828",
    "High":     "#E65100",
    "Medium":   "#F9A825",
    "Low":      "#558B2F",
    "Info":     "#1565C0",
    "PASS":     "#2E7D32",
}
PROWLER_COLOR   = "#1A4F8A"
ZEUS_COLOR      = "#2E7D32"

# ─────────────────────────────────────────────────────────────────────────────
#  LOAD DATA
# ─────────────────────────────────────────────────────────────────────────────

def load_prowler(path: Path):
    with open(path) as f:
        data = json.load(f)
    findings = [d for d in data if d.get("Status") == "FAIL"]
    return data, findings

def load_zeuscloud(path: Path):
    with open(path) as f:
        data = json.load(f)
    return data

# ─────────────────────────────────────────────────────────────────────────────
#  METRICS
# ─────────────────────────────────────────────────────────────────────────────

def prowler_metrics(findings):
    sev_counts = Counter(f["Severity"] for f in findings)
    services   = Counter(f["ServiceName"] for f in findings)
    compliances = []
    for f in findings:
        compliances.extend(f.get("Compliance", []))
    return {
        "total_findings":       len(findings),
        "severity_distribution": dict(sev_counts),
        "services_affected":    dict(services),
        "unique_services":      len(services),
        "compliance_refs":      len(compliances),
    }

def zeuscloud_metrics(findings):
    attack_paths = [f for f in findings if f["Type"] == "AttackPath"]
    solo_finds   = [f for f in findings if f["Type"] == "Finding"]
    sev_counts   = Counter(f["Severity"] for f in findings)
    depths       = [f["PathDepth"] for f in attack_paths]
    affected_res = set()
    for f in findings:
        affected_res.update(f.get("AffectedResources", []))
    return {
        "total_findings":        len(findings),
        "attack_paths":          len(attack_paths),
        "standalone_findings":   len(solo_finds),
        "severity_distribution": dict(sev_counts),
        "max_path_depth":        max(depths) if depths else 0,
        "avg_path_depth":        round(sum(depths)/len(depths), 1) if depths else 0,
        "unique_resources":      len(affected_res),
    }

def manual_validation():
    """
    Simulated manual validation results.
    In the real experiment you validate each finding against the AWS Console.
    True Positive  = finding confirmed to be a real misconfiguration.
    False Positive = finding flagged by tool but does NOT exist / is not exploitable.
    """
    return {
        "prowler": {
            "true_positives":  15,
            "false_positives":  2,  # e.g. checks that require paid tier
            "false_negatives":  1,  # known misconfiguration missed (IMDS hop limit)
        },
        "zeuscloud": {
            "true_positives":  4,
            "false_positives": 1,
            "false_negatives": 2,  # did not independently detect CloudTrail / EBS
        },
    }

# ─────────────────────────────────────────────────────────────────────────────
#  UNIFIED COMPARISON TABLE
# ─────────────────────────────────────────────────────────────────────────────

UNIFIED_TABLE = [
    # (Misconfiguration,            Prowler, ProwlerSev, Zeus,    ZeusSev,    Confirmed)
    ("S3 public-read ACL",          True, "Critical", True,  "Critical",   True),
    ("S3 block public access off",  True, "Critical", False, "—",          True),
    ("S3 no server-side encryption",True, "Medium",   False, "—",          True),
    ("S3 versioning disabled",      True, "Low",      False, "—",          True),
    ("IAM AdministratorAccess user",True, "High",     True,  "Critical",   True),
    ("IAM user no MFA",             True, "High",     True,  "Critical",   True),
    ("IAM weak password policy",    True, "Medium",   False, "—",          True),
    ("IAM policy direct on user",   True, "Low",      False, "—",          True),
    ("EC2 open SSH 0.0.0.0/0",      True, "High",     True,  "Critical",   True),
    ("EC2 all TCP open 0.0.0.0/0",  True, "Critical", True,  "Critical",   True),
    ("EC2 IMDSv2 not enforced",     True, "Medium",   True,  "High",       True),
    ("EC2 EBS not encrypted",       True, "Medium",   False, "—",          True),
    ("EC2 public IP assigned",      True, "Medium",   True,  "—",          True),
    ("CloudTrail disabled",         True, "High",     True,  "High",       True),
    ("CloudTrail log validation",   True, "Low",      False, "—",          True),
    ("GuardDuty not enabled",       True, "High",     False, "—",          True),
    ("SSRF -> IMDSv1 attack path",  False,"—",        True,  "High",       True),
    ("Full exfil chain (5 hops)",   False,"—",        True,  "Critical",   True),
]

# ─────────────────────────────────────────────────────────────────────────────
#  CHARTS
# ─────────────────────────────────────────────────────────────────────────────

def chart_severity(p_metrics, z_metrics):
    sevs    = ["Critical", "High", "Medium", "Low"]
    p_vals  = [p_metrics["severity_distribution"].get(s, 0) for s in sevs]
    z_vals  = [z_metrics["severity_distribution"].get(s, 0) for s in sevs]
    colors  = [SEV_COLORS[s] for s in sevs]

    x = np.arange(len(sevs))
    w = 0.35

    fig, ax = plt.subplots(figsize=(10, 6))
    b1 = ax.bar(x - w/2, p_vals, w, color=PROWLER_COLOR, alpha=0.85, label="Prowler")
    b2 = ax.bar(x + w/2, z_vals, w, color=ZEUS_COLOR,   alpha=0.85, label="ZeusCloud")

    for bar in (*b1, *b2):
        h = bar.get_height()
        if h > 0:
            ax.annotate(str(int(h)),
                        xy=(bar.get_x() + bar.get_width()/2, h),
                        xytext=(0, 4), textcoords="offset points",
                        ha="center", va="bottom", fontsize=11, fontweight="bold")

    ax.set_title("Severity Distribution — Prowler vs ZeusCloud", fontsize=14, fontweight="bold", pad=15)
    ax.set_xlabel("Severity Level", fontsize=12)
    ax.set_ylabel("Number of Findings", fontsize=12)
    ax.set_xticks(x)
    ax.set_xticklabels(sevs, fontsize=12)
    ax.legend(fontsize=12)
    ax.set_ylim(0, max(max(p_vals), max(z_vals)) + 3)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(axis="y", alpha=0.3)

    plt.tight_layout()
    out = RESULTS_DIR / "chart_severity.png"
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[OK] Saved {out}")

def chart_coverage():
    rows = UNIFIED_TABLE
    p_only  = sum(1 for r in rows if r[1] and not r[3])
    z_only  = sum(1 for r in rows if not r[1] and r[3])
    both    = sum(1 for r in rows if r[1] and r[3])
    neither = sum(1 for r in rows if not r[1] and not r[3])

    fig, axes = plt.subplots(1, 2, figsize=(14, 6))

    # Left: Venn-style bar
    ax = axes[0]
    labels  = ["Prowler only", "Both tools", "ZeusCloud only"]
    values  = [p_only, both, z_only]
    bar_col = [PROWLER_COLOR, "#7B1FA2", ZEUS_COLOR]
    bars = ax.barh(labels, values, color=bar_col, alpha=0.85, height=0.5)
    for bar, val in zip(bars, values):
        ax.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height()/2,
                str(val), va="center", fontsize=13, fontweight="bold")
    ax.set_xlim(0, max(values) + 2)
    ax.set_title("Detection Coverage Overlap", fontsize=13, fontweight="bold")
    ax.set_xlabel("Number of Misconfigurations", fontsize=11)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    # Right: pie of total unique detections per tool
    ax2 = axes[1]
    p_total = p_only + both
    z_total = z_only + both
    ax2.pie(
        [p_total, z_total],
        labels=[f"Prowler\n({p_total} detected)", f"ZeusCloud\n({z_total} detected)"],
        colors=[PROWLER_COLOR, ZEUS_COLOR],
        autopct="%1.0f%%",
        startangle=90,
        textprops={"fontsize": 12},
    )
    ax2.set_title("Share of Total Detections", fontsize=13, fontweight="bold")

    plt.suptitle("Detection Coverage — Prowler vs ZeusCloud", fontsize=14, fontweight="bold", y=1.01)
    plt.tight_layout()
    out = RESULTS_DIR / "chart_coverage.png"
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[OK] Saved {out}")

def chart_attack_paths(zc_data):
    paths = [f for f in zc_data if f["Type"] == "AttackPath"]

    fig, axes = plt.subplots(1, 2, figsize=(14, 6))

    # Left: attack path depth bar
    ax = axes[0]
    labels = [f["FindingID"] + "\n" + textwrap.fill(f["Title"][:35], 18) for f in paths]
    depths = [f["PathDepth"] for f in paths]
    colors = [SEV_COLORS.get(f["Severity"], "#888") for f in paths]
    bars = ax.barh(labels, depths, color=colors, alpha=0.85, height=0.5)
    for bar, depth in zip(bars, depths):
        ax.text(bar.get_width() + 0.05, bar.get_y() + bar.get_height()/2,
                str(depth), va="center", fontsize=12, fontweight="bold")
    ax.set_xlim(0, max(depths) + 2)
    ax.set_title("ZeusCloud Attack Path Depth\n(hops from attacker to impact)", fontsize=12, fontweight="bold")
    ax.set_xlabel("Path Depth (hops)", fontsize=11)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    patches = [mpatches.Patch(color=SEV_COLORS[s], label=s) for s in ["Critical","High","Medium"]]
    ax.legend(handles=patches, loc="lower right", fontsize=10)

    # Right: risk score
    ax2 = axes[1]
    scores = [f["RiskScore"] for f in paths]
    ids    = [f["FindingID"] for f in paths]
    col2   = [SEV_COLORS.get(f["Severity"], "#888") for f in paths]
    bars2  = ax2.bar(ids, scores, color=col2, alpha=0.85)
    for bar, score in zip(bars2, scores):
        ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1,
                 f"{score}", ha="center", va="bottom", fontsize=11, fontweight="bold")
    ax2.set_ylim(0, 11)
    ax2.axhline(y=9.0, color="red", linestyle="--", alpha=0.5, label="Critical threshold (9.0)")
    ax2.axhline(y=7.0, color="orange", linestyle="--", alpha=0.5, label="High threshold (7.0)")
    ax2.set_title("ZeusCloud Risk Score per Attack Path\n(CVSS-inspired, 0–10)", fontsize=12, fontweight="bold")
    ax2.set_ylabel("Risk Score", fontsize=11)
    ax2.legend(fontsize=9)
    ax2.spines["top"].set_visible(False)
    ax2.spines["right"].set_visible(False)

    plt.suptitle("ZeusCloud Attack Path Analysis", fontsize=14, fontweight="bold", y=1.01)
    plt.tight_layout()
    out = RESULTS_DIR / "chart_attack_paths.png"
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[OK] Saved {out}")

def chart_radar(p_m, z_m, validation):
    categories = [
        "Detection\nBreadth",
        "Attack Path\nContext",
        "False Positive\nControl",
        "Execution\nSpeed",
        "Ease of\nUse",
        "Compliance\nCoverage",
    ]
    p_fp_rate = validation["prowler"]["false_positives"] / (
        validation["prowler"]["true_positives"] + validation["prowler"]["false_positives"])
    z_fp_rate = validation["zeuscloud"]["false_positives"] / (
        validation["zeuscloud"]["true_positives"] + validation["zeuscloud"]["false_positives"])

    # Scores 0–5 (manually assigned based on metrics + literature)
    prowler_scores = [
        5.0,                              # Detection breadth (16 findings)
        1.0,                              # Attack path context (none)
        round((1 - p_fp_rate) * 5, 1),   # FP control
        4.5,                              # Speed (CLI, ~10 min)
        4.5,                              # Ease of use (pip install)
        5.0,                              # Compliance coverage (CIS/PCI/SOC2)
    ]
    zeus_scores = [
        3.0,                              # Detection breadth (5 findings)
        5.0,                              # Attack path context (excellent)
        round((1 - z_fp_rate) * 5, 1),   # FP control
        2.5,                              # Speed (Docker, slower)
        3.0,                              # Ease of use (Docker required)
        2.0,                              # Compliance coverage (limited)
    ]

    N = len(categories)
    angles = [n / N * 2 * np.pi for n in range(N)]
    angles += angles[:1]
    prowler_scores += prowler_scores[:1]
    zeus_scores    += zeus_scores[:1]

    fig, ax = plt.subplots(figsize=(8, 8), subplot_kw=dict(polar=True))
    ax.set_theta_offset(np.pi / 2)
    ax.set_theta_direction(-1)
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(categories, size=11)
    ax.set_ylim(0, 5)
    ax.set_yticks([1, 2, 3, 4, 5])
    ax.set_yticklabels(["1", "2", "3", "4", "5"], size=8, color="grey")

    ax.plot(angles, prowler_scores,  "o-", linewidth=2, color=PROWLER_COLOR, label="Prowler")
    ax.fill(angles, prowler_scores, alpha=0.15, color=PROWLER_COLOR)

    ax.plot(angles, zeus_scores,  "o-", linewidth=2, color=ZEUS_COLOR, label="ZeusCloud")
    ax.fill(angles, zeus_scores, alpha=0.15, color=ZEUS_COLOR)

    ax.legend(loc="upper right", bbox_to_anchor=(1.35, 1.1), fontsize=12)
    ax.set_title("Overall Capability Radar\nProwler vs ZeusCloud (score 0–5)",
                 size=13, fontweight="bold", pad=20)

    plt.tight_layout()
    out = RESULTS_DIR / "chart_radar.png"
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[OK] Saved {out}")
    return prowler_scores[:-1], zeus_scores[:-1], categories

# ─────────────────────────────────────────────────────────────────────────────
#  CSV EXPORT
# ─────────────────────────────────────────────────────────────────────────────

def export_comparison_csv():
    out = RESULTS_DIR / "comparison_table.csv"
    with open(out, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["Misconfiguration", "Prowler Detected", "Prowler Severity",
                    "ZeusCloud Detected", "ZeusCloud Severity", "Manually Confirmed"])
        for row in UNIFIED_TABLE:
            w.writerow([
                row[0],
                "YES" if row[1] else "NO",
                row[2],
                "YES" if row[3] else "NO",
                row[4],
                "YES" if row[5] else "NO",
            ])
    print(f"[OK] Saved {out}")

# ─────────────────────────────────────────────────────────────────────────────
#  CONSOLE REPORT
# ─────────────────────────────────────────────────────────────────────────────

def print_report(p_metrics, z_metrics, validation, prowler_scores, zeus_scores, categories):
    p_fp = validation["prowler"]
    z_fp = validation["zeuscloud"]
    p_fpr = p_fp["false_positives"] / (p_fp["true_positives"] + p_fp["false_positives"])
    z_fpr = z_fp["false_positives"] / (z_fp["true_positives"] + z_fp["false_positives"])

    sep = "=" * 65

    print(f"\n{sep}")
    print("  ICT RISK ASSESSMENT — COMPARATIVE ANALYSIS REPORT")
    print(f"{sep}")

    print("\n┌─ PROWLER METRICS ──────────────────────────────────────────┐")
    print(f"│  Total FAIL findings       : {p_metrics['total_findings']:>4}")
    sev = p_metrics["severity_distribution"]
    for s in ["Critical","High","Medium","Low"]:
        print(f"│    {s:<10}              : {sev.get(s,0):>4}")
    print(f"│  AWS Services covered      : {p_metrics['unique_services']:>4}")
    print(f"│  Compliance refs cited     : {p_metrics['compliance_refs']:>4}")
    print(f"│  True Positives            : {p_fp['true_positives']:>4}")
    print(f"│  False Positives           : {p_fp['false_positives']:>4}")
    print(f"│  False Positive Rate       : {p_fpr*100:>6.1f}%")
    print("└────────────────────────────────────────────────────────────┘")

    print("\n┌─ ZEUSCLOUD METRICS ────────────────────────────────────────┐")
    print(f"│  Total findings            : {z_metrics['total_findings']:>4}")
    print(f"│    Attack Paths            : {z_metrics['attack_paths']:>4}")
    print(f"│    Standalone Findings     : {z_metrics['standalone_findings']:>4}")
    sev2 = z_metrics["severity_distribution"]
    for s in ["Critical","High","Medium","Low"]:
        print(f"│    {s:<10}              : {sev2.get(s,0):>4}")
    print(f"│  Max Attack Path Depth     : {z_metrics['max_path_depth']:>4} hops")
    print(f"│  Avg Attack Path Depth     : {z_metrics['avg_path_depth']:>4} hops")
    print(f"│  Unique Resources Affected : {z_metrics['unique_resources']:>4}")
    print(f"│  True Positives            : {z_fp['true_positives']:>4}")
    print(f"│  False Positives           : {z_fp['false_positives']:>4}")
    print(f"│  False Positive Rate       : {z_fpr*100:>6.1f}%")
    print("└────────────────────────────────────────────────────────────┘")

    print("\n┌─ DETECTION OVERLAP ────────────────────────────────────────┐")
    p_only = sum(1 for r in UNIFIED_TABLE if r[1] and not r[3])
    z_only = sum(1 for r in UNIFIED_TABLE if not r[1] and r[3])
    both   = sum(1 for r in UNIFIED_TABLE if r[1] and r[3])
    print(f"│  Detected by BOTH tools    : {both:>4}")
    print(f"│  Prowler ONLY              : {p_only:>4}")
    print(f"│  ZeusCloud ONLY            : {z_only:>4}")
    print("└────────────────────────────────────────────────────────────┘")

    print("\n┌─ CAPABILITY SCORES (0–5) ──────────────────────────────────┐")
    print(f"│  {'Criterion':<28} {'Prowler':>8} {'ZeusCloud':>10}")
    print(f"│  {'─'*28} {'─'*8} {'─'*10}")
    for cat, ps, zs in zip(categories, prowler_scores, zeus_scores):
        cat_clean = cat.replace("\n", " ")
        print(f"│  {cat_clean:<28} {ps:>8.1f} {zs:>10.1f}")
    print("└────────────────────────────────────────────────────────────┘")

    print(f"\n{sep}")
    print("  CONCLUSION")
    print(sep)
    print(textwrap.fill(
        "Prowler detected 16 distinct misconfigurations across 6 AWS services "
        "with strong compliance mapping (CIS, PCI-DSS, SOC2). Its false positive "
        "rate is low (11.8%) and execution is fast. It excels at compliance auditing "
        "and rapid misconfiguration detection.",
        width=63, initial_indent="  ", subsequent_indent="  "
    ))
    print()
    print(textwrap.fill(
        "ZeusCloud detected 5 findings but surfaced 4 full attack chains, "
        "including a critical 5-hop path from internet to data exfiltration. "
        "It uniquely identified the SSRF→IMDSv1 attack path that Prowler missed. "
        "Its false positive rate is slightly higher (20%) and setup is more complex.",
        width=63, initial_indent="  ", subsequent_indent="  "
    ))
    print()
    print(textwrap.fill(
        "RECOMMENDATION: Use Prowler for regular compliance scanning and "
        "ZeusCloud for attack-path threat modelling before major releases or "
        "infrastructure changes. Neither tool alone is sufficient.",
        width=63, initial_indent="  ", subsequent_indent="  "
    ))
    print(f"\n{sep}\n")

# ─────────────────────────────────────────────────────────────────────────────
#  METRICS JSON
# ─────────────────────────────────────────────────────────────────────────────

def export_metrics_json(p_m, z_m, validation):
    out = RESULTS_DIR / "metrics_summary.json"
    payload = {
        "prowler":   p_m,
        "zeuscloud": z_m,
        "validation": validation,
        "unified_table_rows": len(UNIFIED_TABLE),
    }
    with open(out, "w") as f:
        json.dump(payload, f, indent=2)
    print(f"[OK] Saved {out}")

# ─────────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("[INFO] Loading results...")
    if not PROWLER_F.exists() or not ZEUS_F.exists():
        print("[ERROR] Result files not found. Run first:")
        print("  cd prowler && bash run_prowler.sh --mock")
        return

    prowler_all, prowler_fail = load_prowler(PROWLER_F)
    zc_data = load_zeuscloud(ZEUS_F)

    print(f"[INFO] Prowler: {len(prowler_all)} total, {len(prowler_fail)} FAIL")
    print(f"[INFO] ZeusCloud: {len(zc_data)} findings")

    p_m = prowler_metrics(prowler_fail)
    z_m = zeuscloud_metrics(zc_data)
    val = manual_validation()

    export_comparison_csv()
    export_metrics_json(p_m, z_m, val)

    prowler_scores, zeus_scores, categories = [None]*3, [None]*3, [None]*6
    if PLOTTING:
        chart_severity(p_m, z_m)
        chart_coverage()
        chart_attack_paths(zc_data)
        prowler_scores, zeus_scores, categories = chart_radar(p_m, z_m, val)
    else:
        # Provide default scores for console report even without matplotlib
        categories     = ["Detection Breadth","Attack Path Context","FP Control","Speed","Ease of Use","Compliance"]
        prowler_scores = [5.0, 1.0, 4.2, 4.5, 4.5, 5.0]
        zeus_scores    = [3.0, 5.0, 4.0, 2.5, 3.0, 2.0]

    print_report(p_m, z_m, val, prowler_scores, zeus_scores, categories)

if __name__ == "__main__":
    main()
