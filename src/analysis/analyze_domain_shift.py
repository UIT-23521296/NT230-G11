"""
================================================================================
DOMAIN SHIFT DEEP ANALYSIS
================================================================================
Phan tich chi tiet nguyen nhan cu the khien mo hinh M-FastText-2 
bi sut giam do chinh xac tren tap du lieu moi.

So sanh tung nhom dac trung:
  - Textual Features (13D)
  - Token Features (34D) 
  - AST Features (29D)
  - FastText Embedding prediction (2D)

giua ma doc trong tap MPSD (goc) va ma doc trong tap moi (pentesting tools).
================================================================================
"""

import os
import sys
import json
import pickle
import numpy as np
import warnings
warnings.filterwarnings('ignore')

from collections import Counter

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

# Import core feature extraction
import sys
import os
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)
from src.core import m_fasttext2_model_78dim as core

# ============================================================
# CONFIGURATION
# ============================================================
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
RESULTS_DIR = os.path.join(BASE_DIR, "results", "78dim")
MPSD_MAL_DIR = os.path.join(BASE_DIR, "mpsd", "malicious_pure")
NEW_MAL_DIR = os.path.join(BASE_DIR, "new_dataset", "malicious")
NEW_BEN_DIR = os.path.join(BASE_DIR, "new_dataset", "benign")

# Feature group indices (in the 376D raw vector BEFORE compression)
# [0:300]   = FastText embedding
# [300:313] = Textual features (13D)
# [313:314] = Token: total_rating (1D)
# [314:347] = Token: member ratios (33D)
# [347:376] = AST features (29D)

FT_START, FT_END = 0, 300
TEXT_START, TEXT_END = 300, 313
TOKEN_RATING_IDX = 313
TOKEN_MEMBER_START, TOKEN_MEMBER_END = 314, 347
AST_START, AST_END = 347, 376

TEXTUAL_NAMES = [
    "Shellcode (0/1)", "Entropy",
    "Top char 1 (ASCII)", "Top char 2", "Top char 3", "Top char 4", "Top char 5",
    "Num strings", "Max string len", "Avg string len",
    "URL/IP (0/1)", "Total vars", "Special vars"
]

AST_23_NAMES = list(core.AST_23_NODE_PATTERNS.keys())
AST_5_NAMES = list(core.AST_5_SPECIAL_PATTERNS.keys())
AST_NAMES = AST_23_NAMES + AST_5_NAMES + ["AST_Depth"]


def main():
    print()
    print("=" * 70)
    print("  DOMAIN SHIFT DEEP ANALYSIS")
    print("  So sanh dac trung giua ma doc MPSD vs ma doc moi")
    print("=" * 70)

    # ── 1. Load model ──
    print("\n[1] Loading saved model...")
    ft_path = os.path.join(RESULTS_DIR, "m_fasttext2.model")
    fasttext_model = GensimFastText.load(ft_path)
    print(f"  FastText model loaded")

    tokens_path = os.path.join(RESULTS_DIR, "top_tokens_78dim.json")
    with open(tokens_path, 'r') as f:
        token_config = json.load(f)
    top_functions_scores = token_config["top_functions_scores"]
    top_members = token_config["top_members"]
    print(f"  Token config loaded ({len(top_functions_scores)} funcs, {len(top_members)} members)")

    ft_clf_path = os.path.join(RESULTS_DIR, "ft_classifier.pkl")
    with open(ft_clf_path, 'rb') as f:
        ft_classifier = pickle.load(f)

    rf_path = os.path.join(RESULTS_DIR, "rf_classifier.pkl")
    with open(rf_path, 'rb') as f:
        rf_model = pickle.load(f)
    print(f"  RF classifier loaded")

    # ── 2. Load scripts ──
    print("\n[2] Loading scripts...")
    mpsd_mal_scripts, _ = core.load_scripts(MPSD_MAL_DIR, "  MPSD malicious")
    new_mal_scripts, new_mal_files = core.load_scripts(NEW_MAL_DIR, "  New malicious")
    new_ben_scripts, _ = core.load_scripts(NEW_BEN_DIR, "  New benign")

    mpsd_mal_scripts = [s for s in mpsd_mal_scripts if len(s.strip()) > 0]
    new_mal_scripts_clean = [(s, f) for s, f in zip(new_mal_scripts, new_mal_files) if len(s.strip()) > 0]
    new_mal_scripts = [s for s, f in new_mal_scripts_clean]
    new_mal_files = [f for s, f in new_mal_scripts_clean]

    print(f"\n  MPSD malicious: {len(mpsd_mal_scripts)} scripts")
    print(f"  New malicious:  {len(new_mal_scripts)} scripts")

    # ── 3. Extract raw features (376D) ──
    print("\n[3] Extracting features (376D raw)...")
    mpsd_features = core.extract_all_features(
        mpsd_mal_scripts, fasttext_model, top_functions_scores, top_members,
        desc="  MPSD malicious features"
    )
    new_mal_features = core.extract_all_features(
        new_mal_scripts, fasttext_model, top_functions_scores, top_members,
        desc="  New malicious features"
    )
    new_ben_features = core.extract_all_features(
        new_ben_scripts, fasttext_model, top_functions_scores, top_members,
        desc="  New benign features"
    )

    mpsd_features = np.nan_to_num(mpsd_features, nan=0.0, posinf=0.0, neginf=0.0)
    new_mal_features = np.nan_to_num(new_mal_features, nan=0.0, posinf=0.0, neginf=0.0)
    new_ben_features = np.nan_to_num(new_ben_features, nan=0.0, posinf=0.0, neginf=0.0)

    # ── 4. Classify new malicious → find FN (missed) vs TP (caught) ──
    print("\n[4] Classifying new malicious scripts...")
    X_ft = new_mal_features[:, FT_START:FT_END]
    X_manual = new_mal_features[:, FT_END:]
    ft_pred = ft_classifier.predict(X_ft).reshape(-1, 1)
    ft_proba = ft_classifier.predict_proba(X_ft)[:, 1].reshape(-1, 1)
    X_78d = np.hstack([ft_pred, ft_proba, X_manual])
    y_pred = rf_model.predict(X_78d)

    caught_idx = np.where(y_pred == 1)[0]  # True Positive
    missed_idx = np.where(y_pred == 0)[0]  # False Negative

    print(f"  Caught (TP): {len(caught_idx)} scripts")
    print(f"  Missed (FN): {len(missed_idx)} scripts")

    # ── 5. DEEP COMPARISON ──
    print("\n" + "=" * 70)
    print("  FEATURE GROUP COMPARISON")
    print("=" * 70)

    report_lines = []
    report_lines.append("=" * 70)
    report_lines.append("  DOMAIN SHIFT DEEP ANALYSIS REPORT")
    report_lines.append("=" * 70)
    report_lines.append("")

    # ─── 5A. TEXTUAL FEATURES ───
    print("\n--- [A] TEXTUAL FEATURES (13D) ---")
    report_lines.append("--- [A] TEXTUAL FEATURES (13D) ---")
    report_lines.append("")

    mpsd_text = mpsd_features[:, TEXT_START:TEXT_END]
    new_mal_text = new_mal_features[:, TEXT_START:TEXT_END]
    new_ben_text = new_ben_features[:, TEXT_START:TEXT_END]
    missed_text = new_mal_features[missed_idx, TEXT_START:TEXT_END]
    caught_text = new_mal_features[caught_idx, TEXT_START:TEXT_END]

    header = f"  {'Feature':<25} {'MPSD Mal':>10} {'New Mal':>10} {'New Ben':>10} {'Missed':>10} {'Caught':>10}"
    print(header)
    report_lines.append(header)
    print("  " + "-" * 77)
    report_lines.append("  " + "-" * 77)

    for i, name in enumerate(TEXTUAL_NAMES):
        mpsd_val = np.mean(mpsd_text[:, i])
        new_mal_val = np.mean(new_mal_text[:, i])
        new_ben_val = np.mean(new_ben_text[:, i])
        missed_val = np.mean(missed_text[:, i]) if len(missed_idx) > 0 else 0
        caught_val = np.mean(caught_text[:, i]) if len(caught_idx) > 0 else 0
        line = f"  {name:<25} {mpsd_val:>10.3f} {new_mal_val:>10.3f} {new_ben_val:>10.3f} {missed_val:>10.3f} {caught_val:>10.3f}"
        print(line)
        report_lines.append(line)

    report_lines.append("")

    # ─── 5B. TOKEN FEATURES ───
    print("\n--- [B] TOKEN FEATURES ---")
    report_lines.append("--- [B] TOKEN FEATURES ---")
    report_lines.append("")

    mpsd_rating = mpsd_features[:, TOKEN_RATING_IDX]
    new_mal_rating = new_mal_features[:, TOKEN_RATING_IDX]
    new_ben_rating = new_ben_features[:, TOKEN_RATING_IDX]
    missed_rating = new_mal_features[missed_idx, TOKEN_RATING_IDX]
    caught_rating = new_mal_features[caught_idx, TOKEN_RATING_IDX]

    header2 = f"  {'Metric':<30} {'MPSD Mal':>10} {'New Mal':>10} {'New Ben':>10} {'Missed':>10} {'Caught':>10}"
    print(header2)
    report_lines.append(header2)
    print("  " + "-" * 82)
    report_lines.append("  " + "-" * 82)

    for label, arr_m, arr_n, arr_b, arr_miss, arr_catch in [
        ("Total Rating (mean)", mpsd_rating, new_mal_rating, new_ben_rating, missed_rating, caught_rating),
    ]:
        line = f"  {label:<30} {np.mean(arr_m):>10.2f} {np.mean(arr_n):>10.2f} {np.mean(arr_b):>10.2f} {np.mean(arr_miss):>10.2f} {np.mean(arr_catch):>10.2f}"
        print(line)
        report_lines.append(line)
        line = f"  {'  (median)':<30} {np.median(arr_m):>10.2f} {np.median(arr_n):>10.2f} {np.median(arr_b):>10.2f} {np.median(arr_miss):>10.2f} {np.median(arr_catch):>10.2f}"
        print(line)
        report_lines.append(line)
        line = f"  {'  (std)':<30} {np.std(arr_m):>10.2f} {np.std(arr_n):>10.2f} {np.std(arr_b):>10.2f} {np.std(arr_miss):>10.2f} {np.std(arr_catch):>10.2f}"
        print(line)
        report_lines.append(line)

    # Percentage of scripts with positive rating
    pos_mpsd = np.mean(mpsd_rating > 0) * 100
    pos_new_mal = np.mean(new_mal_rating > 0) * 100
    pos_new_ben = np.mean(new_ben_rating > 0) * 100
    pos_missed = np.mean(missed_rating > 0) * 100 if len(missed_idx) > 0 else 0
    pos_caught = np.mean(caught_rating > 0) * 100 if len(caught_idx) > 0 else 0
    line = f"  {'  (% positive rating)':<30} {pos_mpsd:>9.1f}% {pos_new_mal:>9.1f}% {pos_new_ben:>9.1f}% {pos_missed:>9.1f}% {pos_caught:>9.1f}%"
    print(line)
    report_lines.append(line)

    report_lines.append("")

    # ─── 5C. AST FEATURES ───
    print("\n--- [C] AST FEATURES (29D) ---")
    report_lines.append("--- [C] AST FEATURES (29D) ---")
    report_lines.append("")

    mpsd_ast = mpsd_features[:, AST_START:AST_END]
    new_mal_ast = new_mal_features[:, AST_START:AST_END]
    new_ben_ast = new_ben_features[:, AST_START:AST_END]
    missed_ast = new_mal_features[missed_idx, AST_START:AST_END]
    caught_ast = new_mal_features[caught_idx, AST_START:AST_END]

    header3 = f"  {'AST Node':<30} {'MPSD Mal':>10} {'New Mal':>10} {'New Ben':>10} {'Missed':>10} {'Caught':>10}"
    print(header3)
    report_lines.append(header3)
    print("  " + "-" * 82)
    report_lines.append("  " + "-" * 82)

    for i, name in enumerate(AST_NAMES):
        mpsd_v = np.mean(mpsd_ast[:, i])
        new_v = np.mean(new_mal_ast[:, i])
        ben_v = np.mean(new_ben_ast[:, i])
        miss_v = np.mean(missed_ast[:, i]) if len(missed_idx) > 0 else 0
        catch_v = np.mean(caught_ast[:, i]) if len(caught_idx) > 0 else 0
        line = f"  {name:<30} {mpsd_v:>10.2f} {new_v:>10.2f} {ben_v:>10.2f} {miss_v:>10.2f} {catch_v:>10.2f}"
        print(line)
        report_lines.append(line)

    report_lines.append("")

    # ─── 5D. FASTTEXT CLASSIFIER PREDICTION ───
    print("\n--- [D] FASTTEXT CLASSIFIER PREDICTION (Compressed 2D) ---")
    report_lines.append("--- [D] FASTTEXT CLASSIFIER PREDICTION (Compressed 2D) ---")
    report_lines.append("")

    # MPSD malicious
    mpsd_ft = mpsd_features[:, FT_START:FT_END]
    mpsd_ft_pred = ft_classifier.predict(mpsd_ft)
    mpsd_ft_proba = ft_classifier.predict_proba(mpsd_ft)[:, 1]

    # New malicious
    new_ft_pred = ft_classifier.predict(X_ft)
    new_ft_proba = ft_classifier.predict_proba(X_ft)[:, 1]

    # New benign
    ben_ft = new_ben_features[:, FT_START:FT_END]
    ben_ft_pred = ft_classifier.predict(ben_ft)
    ben_ft_proba = ft_classifier.predict_proba(ben_ft)[:, 1]

    missed_ft_pred = new_ft_pred[missed_idx]
    missed_ft_proba = new_ft_proba[missed_idx]
    caught_ft_pred = new_ft_pred[caught_idx]
    caught_ft_proba = new_ft_proba[caught_idx]

    header4 = f"  {'Metric':<35} {'MPSD Mal':>10} {'New Mal':>10} {'New Ben':>10} {'Missed':>10} {'Caught':>10}"
    print(header4)
    report_lines.append(header4)
    print("  " + "-" * 87)
    report_lines.append("  " + "-" * 87)

    line = f"  {'FT pred=1 (malicious) %':<35} {np.mean(mpsd_ft_pred)*100:>9.1f}% {np.mean(new_ft_pred)*100:>9.1f}% {np.mean(ben_ft_pred)*100:>9.1f}% {np.mean(missed_ft_pred)*100:>9.1f}% {np.mean(caught_ft_pred)*100:>9.1f}%"
    print(line)
    report_lines.append(line)
    line = f"  {'FT confidence (mean proba)':<35} {np.mean(mpsd_ft_proba):>10.4f} {np.mean(new_ft_proba):>10.4f} {np.mean(ben_ft_proba):>10.4f} {np.mean(missed_ft_proba):>10.4f} {np.mean(caught_ft_proba):>10.4f}"
    print(line)
    report_lines.append(line)
    line = f"  {'FT confidence (median proba)':<35} {np.median(mpsd_ft_proba):>10.4f} {np.median(new_ft_proba):>10.4f} {np.median(ben_ft_proba):>10.4f} {np.median(missed_ft_proba):>10.4f} {np.median(caught_ft_proba):>10.4f}"
    print(line)
    report_lines.append(line)

    report_lines.append("")

    # ─── 5E. TOP FUNCTION ANALYSIS ───
    print("\n--- [E] TOP FUNCTION CALL ANALYSIS ---")
    report_lines.append("--- [E] TOP FUNCTION CALL ANALYSIS ---")
    report_lines.append("")

    # Count function calls in each group
    mpsd_func_counter = Counter()
    for s in mpsd_mal_scripts[:500]:  # sample for speed
        mpsd_func_counter.update(core.extract_function_calls(s))

    missed_func_counter = Counter()
    for idx in missed_idx:
        missed_func_counter.update(core.extract_function_calls(new_mal_scripts[idx]))

    caught_func_counter = Counter()
    for idx in caught_idx:
        caught_func_counter.update(core.extract_function_calls(new_mal_scripts[idx]))

    new_ben_func_counter = Counter()
    for s in new_ben_scripts[:500]:
        new_ben_func_counter.update(core.extract_function_calls(s))

    # Show which top functions appear differently
    report_lines.append("  Functions in top200 that appear MORE in MISSED malware than MPSD malware:")
    report_lines.append(f"  {'Function':<35} {'MPSD freq':>10} {'Missed freq':>12} {'Score':>6} {'Verdict':<15}")
    report_lines.append("  " + "-" * 80)

    suspicious_funcs = []
    for func, score in sorted(top_functions_scores.items(), key=lambda x: x[1]):
        mpsd_f = mpsd_func_counter.get(func, 0)
        missed_f = missed_func_counter.get(func, 0)
        caught_f = caught_func_counter.get(func, 0)
        # Normalize by number of scripts
        mpsd_norm = mpsd_f / min(500, len(mpsd_mal_scripts))
        missed_norm = missed_f / max(1, len(missed_idx))
        
        if missed_norm > mpsd_norm * 1.5 and missed_f > 5:
            verdict = "BENIGN-scored" if score == -1 else "MAL-scored"
            suspicious_funcs.append((func, mpsd_f, missed_f, score, verdict))

    suspicious_funcs.sort(key=lambda x: x[2], reverse=True)
    for func, mf, misf, sc, verd in suspicious_funcs[:30]:
        line = f"  {func:<35} {mf:>10} {misf:>12} {sc:>+6} {verd:<15}"
        print(line)
        report_lines.append(line)

    report_lines.append("")
    report_lines.append("  Functions that appear in CAUGHT malware but NOT in MISSED:")
    report_lines.append(f"  {'Function':<35} {'Caught freq':>12} {'Missed freq':>12} {'Score':>6}")
    report_lines.append("  " + "-" * 70)

    differentiators = []
    for func, score in top_functions_scores.items():
        caught_f = caught_func_counter.get(func, 0)
        missed_f = missed_func_counter.get(func, 0)
        caught_norm = caught_f / max(1, len(caught_idx))
        missed_norm = missed_f / max(1, len(missed_idx))
        if caught_norm > missed_norm * 3 and caught_f > 3 and score == 1:
            differentiators.append((func, caught_f, missed_f, score))

    differentiators.sort(key=lambda x: x[1], reverse=True)
    for func, cf, mf, sc in differentiators[:20]:
        line = f"  {func:<35} {cf:>12} {mf:>12} {sc:>+6}"
        print(line)
        report_lines.append(line)

    report_lines.append("")

    # ─── 6. SUMMARY & KEY FINDINGS ───
    print("\n" + "=" * 70)
    print("  KEY FINDINGS - NGUYEN NHAN CU THE")
    print("=" * 70)

    report_lines.append("=" * 70)
    report_lines.append("  KEY FINDINGS - NGUYEN NHAN CU THE")
    report_lines.append("=" * 70)
    report_lines.append("")

    findings = []

    # Finding 1: Shellcode
    mpsd_shell = np.mean(mpsd_text[:, 0])
    missed_shell = np.mean(missed_text[:, 0]) if len(missed_idx) > 0 else 0
    caught_shell = np.mean(caught_text[:, 0]) if len(caught_idx) > 0 else 0
    findings.append(f"  1. SHELLCODE: MPSD mal={mpsd_shell:.1%} co shellcode, "
                    f"Missed={missed_shell:.1%}, Caught={caught_shell:.1%}")

    # Finding 2: Entropy
    mpsd_entropy = np.mean(mpsd_text[:, 1])
    missed_entropy = np.mean(missed_text[:, 1]) if len(missed_idx) > 0 else 0
    ben_entropy = np.mean(new_ben_text[:, 1])
    findings.append(f"  2. ENTROPY: MPSD mal={mpsd_entropy:.2f}, "
                    f"Missed={missed_entropy:.2f}, Benign={ben_entropy:.2f}")

    # Finding 3: Token Rating
    findings.append(f"  3. TOKEN RATING: MPSD mal={np.mean(mpsd_rating):.1f}, "
                    f"Missed={np.mean(missed_rating):.1f}, Caught={np.mean(caught_rating):.1f}, "
                    f"Benign={np.mean(new_ben_rating):.1f}")

    # Finding 4: FastText prediction
    findings.append(f"  4. FASTTEXT: MPSD mal {np.mean(mpsd_ft_pred)*100:.1f}% bi goi la malicious, "
                    f"Missed chi {np.mean(missed_ft_pred)*100:.1f}%, "
                    f"Caught {np.mean(caught_ft_pred)*100:.1f}%")

    # Finding 5: URL/IP
    mpsd_url = np.mean(mpsd_text[:, 10])
    missed_url = np.mean(missed_text[:, 10]) if len(missed_idx) > 0 else 0
    findings.append(f"  5. URL/IP: MPSD mal={mpsd_url:.1%} co URL/IP, "
                    f"Missed={missed_url:.1%}")

    # Finding 6: Special vars
    mpsd_specvar = np.mean(mpsd_text[:, 12])
    missed_specvar = np.mean(missed_text[:, 12]) if len(missed_idx) > 0 else 0
    ben_specvar = np.mean(new_ben_text[:, 12])
    findings.append(f"  6. SPECIAL VARS: MPSD mal={mpsd_specvar:.1f}, "
                    f"Missed={missed_specvar:.1f}, Benign={ben_specvar:.1f}")

    for f in findings:
        print(f)
        report_lines.append(f)

    report_lines.append("")

    # ── 7. Save report ──
    report_path = os.path.join(RESULTS_DIR, "domain_shift_analysis.txt")
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(report_lines))
    print(f"\n  Report saved to: {report_path}")

    # ── 8. Generate comparison charts ──
    print("\n[6] Generating analysis charts...")
    
    fig, axes = plt.subplots(2, 2, figsize=(16, 12))
    fig.suptitle('Domain Shift Analysis: MPSD Malware vs New Malware',
                 fontsize=16, fontweight='bold', y=0.98)

    # Chart 1: Textual features comparison
    ax = axes[0, 0]
    key_text_idx = [0, 1, 10, 12]  # shellcode, entropy, url, special_vars
    key_text_names = ["Shellcode\n(0/1)", "Entropy", "URL/IP\n(0/1)", "Special\nVars"]
    x = np.arange(len(key_text_names))
    width = 0.2
    
    # Normalize for visibility
    mpsd_vals = [np.mean(mpsd_text[:, i]) for i in key_text_idx]
    missed_vals = [np.mean(missed_text[:, i]) for i in key_text_idx]
    caught_vals = [np.mean(caught_text[:, i]) for i in key_text_idx]
    ben_vals = [np.mean(new_ben_text[:, i]) for i in key_text_idx]
    
    ax.bar(x - 1.5*width, mpsd_vals, width, label='MPSD Malware', color='#C62828', alpha=0.85)
    ax.bar(x - 0.5*width, missed_vals, width, label='Missed (FN)', color='#FF8F00', alpha=0.85)
    ax.bar(x + 0.5*width, caught_vals, width, label='Caught (TP)', color='#2E7D32', alpha=0.85)
    ax.bar(x + 1.5*width, ben_vals, width, label='New Benign', color='#1565C0', alpha=0.85)
    ax.set_xticks(x)
    ax.set_xticklabels(key_text_names, fontsize=10)
    ax.set_title('Textual Features', fontsize=13, fontweight='bold')
    ax.legend(fontsize=8, loc='upper right')
    ax.set_ylabel('Mean Value')

    # Chart 2: Token Rating distribution
    ax = axes[0, 1]
    data_to_plot = [mpsd_rating, new_mal_rating, caught_rating, missed_rating, new_ben_rating]
    labels = ['MPSD\nMal', 'New\nMal', 'Caught\n(TP)', 'Missed\n(FN)', 'New\nBenign']
    colors = ['#C62828', '#E65100', '#2E7D32', '#FF8F00', '#1565C0']
    bp = ax.boxplot(data_to_plot, labels=labels, patch_artist=True, widths=0.6,
                    showfliers=False)
    for patch, color in zip(bp['boxes'], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)
    ax.axhline(y=0, color='gray', linestyle='--', alpha=0.5)
    ax.set_title('Token Rating Distribution', fontsize=13, fontweight='bold')
    ax.set_ylabel('Total Rating Score')

    # Chart 3: FastText confidence
    ax = axes[1, 0]
    data_proba = [mpsd_ft_proba, new_ft_proba, caught_ft_proba, missed_ft_proba,
                  ben_ft_proba]
    bp2 = ax.boxplot(data_proba, labels=labels, patch_artist=True, widths=0.6,
                     showfliers=False)
    for patch, color in zip(bp2['boxes'], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)
    ax.axhline(y=0.5, color='gray', linestyle='--', alpha=0.5, label='Threshold 0.5')
    ax.set_title('FastText Classifier Confidence', fontsize=13, fontweight='bold')
    ax.set_ylabel('P(malicious)')
    ax.legend(fontsize=9)

    # Chart 4: AST depth comparison
    ax = axes[1, 1]
    ast_depth_idx = len(AST_NAMES) - 1  # last one
    mpsd_depth = mpsd_ast[:, ast_depth_idx]
    missed_depth = missed_ast[:, ast_depth_idx]
    caught_depth = caught_ast[:, ast_depth_idx]
    ben_depth = new_ben_ast[:, ast_depth_idx]
    
    data_depth = [mpsd_depth, caught_depth, missed_depth, ben_depth]
    labels_depth = ['MPSD Mal', 'Caught (TP)', 'Missed (FN)', 'New Benign']
    colors_depth = ['#C62828', '#2E7D32', '#FF8F00', '#1565C0']
    bp3 = ax.boxplot(data_depth, labels=labels_depth, patch_artist=True, widths=0.6,
                     showfliers=False)
    for patch, color in zip(bp3['boxes'], colors_depth):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)
    ax.set_title('AST Nesting Depth', fontsize=13, fontweight='bold')
    ax.set_ylabel('Max Depth')

    plt.tight_layout(rect=[0, 0, 1, 0.95])
    chart_path = os.path.join(RESULTS_DIR, "domain_shift_analysis.png")
    plt.savefig(chart_path, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"  Chart saved: {chart_path}")

    print(f"\n{'=' * 70}")
    print(f"  ANALYSIS COMPLETE!")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    main()
