"""
================================================================================
FAILED CASES ANALYSIS
================================================================================
Mo xe chi tiet cac case bi phan loai sai (False Negative):
- Danh sach file bi bo lot, nhom theo tool
- Case study cu the: tai sao file nay bi lot/bat
- So sanh dac trung giua TP va FN

Dap ung nhan xet giang vien:
  3. "Phan tich ro cac case bi fail khi chay kien truc"
================================================================================
"""

import os
import re
import sys
import json
import pickle
import numpy as np
import warnings
warnings.filterwarnings('ignore')

from collections import Counter, OrderedDict

try:
    from tqdm import tqdm
except ImportError:
    def tqdm(iterable, desc="", ncols=80, **kwargs):
        print(f"  {desc}...")
        return iterable

from gensim.models import FastText as GensimFastText

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns

import sys
import os
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)
from src.core import m_fasttext2_model_78dim as core

# Reuse technique detectors
from src.analysis.analyze_malware_techniques import TECHNIQUES, detect_techniques, classify_source

# ============================================================
# CONFIGURATION
# ============================================================
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
RESULTS_DIR = os.path.join(BASE_DIR, "results", "78dim")
NEW_MAL_DIR = os.path.join(BASE_DIR, "new_dataset", "malicious")
NEW_BEN_DIR = os.path.join(BASE_DIR, "new_dataset", "benign")

FASTTEXT_DIM = 300


def main():
    print()
    print("=" * 70)
    print("  FAILED CASES DEEP ANALYSIS")
    print("  Mo xe chi tiet cac case bi phan loai sai")
    print("=" * 70)

    # ── 1. Load model ──
    print("\n[1] Loading model...")
    ft_path = os.path.join(RESULTS_DIR, "m_fasttext2.model")
    fasttext_model = GensimFastText.load(ft_path)

    tokens_path = os.path.join(RESULTS_DIR, "top_tokens_78dim.json")
    with open(tokens_path, 'r') as f:
        token_config = json.load(f)
    top_functions_scores = token_config["top_functions_scores"]
    top_members = token_config["top_members"]

    ft_clf_path = os.path.join(RESULTS_DIR, "ft_classifier.pkl")
    with open(ft_clf_path, 'rb') as f:
        ft_classifier = pickle.load(f)

    rf_path = os.path.join(RESULTS_DIR, "rf_classifier.pkl")
    with open(rf_path, 'rb') as f:
        rf_model = pickle.load(f)
    print("  Models loaded.")

    # ── 2. Load new malicious scripts ──
    print("\n[2] Loading new malicious scripts...")
    scripts = []
    filenames = []
    ps1_files = sorted([f for f in os.listdir(NEW_MAL_DIR) if f.endswith(('.ps1', '.psm1'))])
    for f in tqdm(ps1_files, desc="  Loading", ncols=80):
        filepath = os.path.join(NEW_MAL_DIR, f)
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as fh:
                content = fh.read()
        except Exception:
            content = ""
        if content.strip():
            scripts.append(content)
            filenames.append(f)

    print(f"  Loaded {len(scripts)} malicious scripts")

    # ── 3. Extract features & predict ──
    print("\n[3] Extracting features & predicting...")
    features = core.extract_all_features(
        scripts, fasttext_model, top_functions_scores, top_members,
        desc="  Extracting features"
    )
    features = np.nan_to_num(features, nan=0.0, posinf=0.0, neginf=0.0)

    # Compress to 78D and predict
    X_ft = features[:, :FASTTEXT_DIM]
    X_manual = features[:, FASTTEXT_DIM:]
    ft_pred = ft_classifier.predict(X_ft).reshape(-1, 1)
    ft_proba = ft_classifier.predict_proba(X_ft)[:, 1].reshape(-1, 1)
    X_78d = np.hstack([ft_pred, ft_proba, X_manual])

    y_pred = rf_model.predict(X_78d)
    y_proba = rf_model.predict_proba(X_78d)[:, 1]

    caught_idx = np.where(y_pred == 1)[0]
    missed_idx = np.where(y_pred == 0)[0]

    print(f"\n  Caught (TP): {len(caught_idx)}")
    print(f"  Missed (FN): {len(missed_idx)}")

    # ── 4. Detect techniques for each file ──
    print("\n[4] Detecting techniques per file...")
    all_techs = []
    for script in tqdm(scripts, desc="  Techniques", ncols=80):
        all_techs.append(detect_techniques(script))

    # ── 5. Build report ──
    report = []
    report.append("=" * 90)
    report.append("  FAILED CASES ANALYSIS REPORT")
    report.append("=" * 90)
    report.append("")

    # --- Section A: By source tool ---
    report.append("=" * 90)
    report.append("  SECTION A: TY LE BAT/LOT THEO TUNG CONG CU")
    report.append("=" * 90)
    report.append("")

    sources_all = [classify_source(f) for f in filenames]
    source_names = ["PowerSploit", "Nishang", "Invoke-Obfuscation", "Empire"]

    header = f"  {'Tool':<22} {'Total':>7} {'Caught':>8} {'Missed':>8} {'Recall':>8}"
    report.append(header)
    report.append("  " + "-" * 56)

    source_stats = {}
    for src in source_names:
        src_indices = [i for i, s in enumerate(sources_all) if s == src]
        src_caught = sum(1 for i in src_indices if y_pred[i] == 1)
        src_missed = sum(1 for i in src_indices if y_pred[i] == 0)
        src_total = len(src_indices)
        recall = src_caught / src_total * 100 if src_total > 0 else 0
        source_stats[src] = {'total': src_total, 'caught': src_caught,
                             'missed': src_missed, 'recall': recall}
        line = f"  {src:<22} {src_total:>7} {src_caught:>8} {src_missed:>8} {recall:>7.1f}%"
        report.append(line)
        print(line)

    report.append("")

    # --- Section B: Technique comparison TP vs FN ---
    report.append("=" * 90)
    report.append("  SECTION B: SO SANH KY THUAT GIUA CAUGHT (TP) VA MISSED (FN)")
    report.append("=" * 90)
    report.append("")

    header2 = f"  {'Ky thuat':<35} {'Caught %':>10} {'Missed %':>10} {'Delta':>8}"
    report.append(header2)
    report.append("  " + "-" * 67)

    tech_names = list(TECHNIQUES.keys())
    for tech in tech_names:
        caught_pct = sum(1 for i in caught_idx if all_techs[i][tech] > 0) / max(1, len(caught_idx)) * 100
        missed_pct = sum(1 for i in missed_idx if all_techs[i][tech] > 0) / max(1, len(missed_idx)) * 100
        delta = caught_pct - missed_pct
        marker = " <<<" if abs(delta) > 20 else ""
        line = f"  {tech:<35} {caught_pct:>9.1f}% {missed_pct:>9.1f}% {delta:>+7.1f}%{marker}"
        report.append(line)
        print(line)

    report.append("")

    # --- Section C: Detailed per-file analysis (top Missed + top Caught) ---
    report.append("=" * 90)
    report.append("  SECTION C: CASE STUDY - FILES DIEN HINH")
    report.append("=" * 90)
    report.append("")

    def file_case_study(idx, verdict):
        """Generate case study for a single file."""
        fname = filenames[idx]
        source = classify_source(fname)
        script = scripts[idx]
        size_kb = len(script.encode('utf-8')) / 1024
        techs = all_techs[idx]
        ft_conf = ft_proba[idx, 0] if ft_proba.ndim > 1 else ft_proba[idx]
        rf_conf = y_proba[idx]

        lines = []
        lines.append(f"  --- {verdict}: {fname} ---")
        lines.append(f"  Source: {source}")
        lines.append(f"  Size: {size_kb:.1f} KB ({len(script)} chars)")
        lines.append(f"  FastText confidence: {ft_conf:.4f}")
        lines.append(f"  RF confidence (malicious): {rf_conf:.4f}")
        lines.append(f"  Techniques detected:")

        active_techs = [(t, c) for t, c in techs.items() if c > 0]
        if active_techs:
            for t, c in sorted(active_techs, key=lambda x: -x[1]):
                lines.append(f"    + {t}: {c} matches")
        else:
            lines.append(f"    (No malware techniques detected)")

        absent_techs = [t for t, c in techs.items() if c == 0]
        lines.append(f"  Techniques ABSENT ({len(absent_techs)}):")
        for t in absent_techs[:5]:
            lines.append(f"    - {t}")
        if len(absent_techs) > 5:
            lines.append(f"    ... and {len(absent_techs) - 5} more")

        # Quick snippet
        first_lines = script.strip().split('\n')[:5]
        lines.append(f"  First 5 lines of code:")
        for l in first_lines:
            lines.append(f"    | {l[:100]}")

        lines.append("")
        return lines

    # Select case studies
    report.append("  === MISSED (False Negative) - Tai sao mo hinh bo lot? ===")
    report.append("")

    # Pick diverse missed cases: 1 from each source
    missed_by_source = {}
    for idx in missed_idx:
        src = classify_source(filenames[idx])
        if src not in missed_by_source:
            missed_by_source[src] = idx

    # Also pick the missed file with highest RF confidence (closest to being caught)
    if len(missed_idx) > 0:
        closest_miss_idx = missed_idx[np.argmax(y_proba[missed_idx])]

    case_indices = list(missed_by_source.values())
    if len(missed_idx) > 0 and closest_miss_idx not in case_indices:
        case_indices.append(closest_miss_idx)

    for idx in case_indices[:5]:
        for line in file_case_study(idx, "MISSED"):
            report.append(line)

    report.append("  === CAUGHT (True Positive) - Tai sao mo hinh bat duoc? ===")
    report.append("")

    # Pick caught cases with highest confidence
    if len(caught_idx) > 0:
        top_caught = caught_idx[np.argsort(-y_proba[caught_idx])][:3]
        for idx in top_caught:
            for line in file_case_study(idx, "CAUGHT"):
                report.append(line)

    # --- Section D: Full file list ---
    report.append("=" * 90)
    report.append("  SECTION D: DANH SACH DAY DU CAC FILE BI BO LOT (MISSED)")
    report.append("=" * 90)
    report.append("")
    report.append(f"  {'#':<4} {'Filename':<55} {'Source':<18} {'RF Conf':>8} {'Techniques':>5}")
    report.append("  " + "-" * 92)

    for rank, idx in enumerate(sorted(missed_idx, key=lambda i: -y_proba[i]), 1):
        fname = filenames[idx][:52]
        src = classify_source(filenames[idx])
        conf = y_proba[idx]
        n_techs = sum(1 for v in all_techs[idx].values() if v > 0)
        report.append(f"  {rank:<4} {fname:<55} {src:<18} {conf:>8.4f} {n_techs:>5}")

    report.append("")

    # ── 6. Save ──
    report_path = os.path.join(RESULTS_DIR, "failed_cases_analysis.txt")
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(report))
    print(f"\n  Report saved: {report_path}")

    # ── 7. Chart ──
    print("\n[5] Generating charts...")

    fig, axes = plt.subplots(1, 2, figsize=(16, 7))
    fig.suptitle('Failed Cases Analysis', fontsize=16, fontweight='bold')

    # Chart 1: Recall by source
    ax = axes[0]
    src_labels = list(source_stats.keys())
    src_recalls = [source_stats[s]['recall'] for s in src_labels]
    src_totals = [source_stats[s]['total'] for s in src_labels]
    colors = ['#E65100', '#2E7D32', '#7B1FA2', '#1565C0']

    bars = ax.bar(src_labels, src_recalls, color=colors, alpha=0.85, edgecolor='white')
    for bar, total, recall in zip(bars, src_totals, src_recalls):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                f'{recall:.1f}%\n(n={total})', ha='center', va='bottom',
                fontsize=10, fontweight='bold')
    ax.set_ylabel('Recall (%)', fontsize=12)
    ax.set_title('Detection Rate by Tool', fontsize=13, fontweight='bold')
    ax.set_ylim(0, 100)

    # Chart 2: Technique prevalence in Caught vs Missed
    ax2 = axes[1]
    x = np.arange(len(tech_names))
    width = 0.35

    caught_pcts = []
    missed_pcts = []
    for tech in tech_names:
        cp = sum(1 for i in caught_idx if all_techs[i][tech] > 0) / max(1, len(caught_idx)) * 100
        mp = sum(1 for i in missed_idx if all_techs[i][tech] > 0) / max(1, len(missed_idx)) * 100
        caught_pcts.append(cp)
        missed_pcts.append(mp)

    ax2.barh(x + width/2, caught_pcts, width, label='Caught (TP)',
             color='#2E7D32', alpha=0.85)
    ax2.barh(x - width/2, missed_pcts, width, label='Missed (FN)',
             color='#C62828', alpha=0.85)

    ax2.set_yticks(x)
    short_names = [t.split('(')[0].strip() if len(t) > 25 else t for t in tech_names]
    ax2.set_yticklabels(short_names, fontsize=9)
    ax2.set_xlabel('% Scripts', fontsize=12)
    ax2.set_title('Techniques: Caught vs Missed', fontsize=13, fontweight='bold')
    ax2.legend(fontsize=10)
    ax2.invert_yaxis()

    plt.tight_layout(rect=[0, 0, 1, 0.95])
    chart_path = os.path.join(RESULTS_DIR, "failed_cases_analysis.png")
    plt.savefig(chart_path, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"  Chart saved: {chart_path}")

    print(f"\n{'=' * 70}")
    print(f"  FAILED CASES ANALYSIS COMPLETE!")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    main()
