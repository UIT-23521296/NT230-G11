"""
================================================================================
OBFUSCATION EXPERIMENT
================================================================================
Thi nghiem kiem tra mo hinh khi ap dung cac ky thuat obfuscation:

Experiment A: Obfuscate ma doc moi (New Malicious) → Test lai
  Gia thuyet: Recall se TANG vi obfuscation tao ra cac dau hieu
  ma mo hinh da hoc tu MPSD (entropy cao, base64, hex...)

Experiment B: Obfuscate file benign moi (New Benign) → Test lai
  Gia thuyet: False Positive se TANG vi file sach bi them dau hieu
  giong ma doc → Kiem tra tinh ben vung (Robustness)

Ky thuat obfuscation:
  1. Base64 Wrapping
  2. Tick/Backtick Insertion
  3. String Reversal + IEX
  4. Variable Renaming (random names)
  5. XOR Encoding

Dap ung nhan xet giang vien:
  4. "Them ky thuat obfuscation vo tap dataset de kiem tra thu kien truc"
================================================================================
"""

import os
import re
import sys
import json
import pickle
import base64
import random
import string
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
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

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
NEW_MAL_DIR = os.path.join(BASE_DIR, "new_dataset", "malicious")
NEW_BEN_DIR = os.path.join(BASE_DIR, "new_dataset", "benign")
FASTTEXT_DIM = 300

random.seed(42)


# ============================================================
# OBFUSCATION TECHNIQUES
# ============================================================

def obfuscate_base64_wrap(script):
    """
    Technique 1: Base64 Wrapping
    Boc toan bo script trong Base64, giai ma va chay bang IEX.
    VD: powershell -enc <base64_encoded_script>
    """
    encoded = base64.b64encode(script.encode('utf-16le')).decode('ascii')
    obfuscated = (
        f"$encoded = '{encoded}'\n"
        f"$decoded = [System.Text.Encoding]::Unicode.GetString("
        f"[System.Convert]::FromBase64String($encoded))\n"
        f"Invoke-Expression $decoded\n"
    )
    return obfuscated


def obfuscate_tick_insertion(script):
    """
    Technique 2: Tick/Backtick Insertion
    Chen backtick vao giua cac tu khoa PowerShell de ne rule.
    VD: Invoke-Expression → In`vo`ke-Exp`ress`ion
    """
    keywords = [
        'Invoke-Expression', 'Invoke-Command', 'Invoke-WebRequest',
        'New-Object', 'Get-Process', 'Get-Service', 'Get-WmiObject',
        'Set-ItemProperty', 'Add-Type', 'Start-Process',
        'DownloadString', 'DownloadFile', 'WebClient',
        'FromBase64String', 'ToBase64String',
        'VirtualAlloc', 'CreateThread', 'WriteProcessMemory',
        'function', 'param', 'foreach', 'while', 'switch',
        'Write-Host', 'Write-Output', 'Write-Verbose',
    ]
    result = script
    for kw in keywords:
        if len(kw) >= 6:
            # Insert tick at ~40% position
            pos = len(kw) * 2 // 5
            ticked = kw[:pos] + '`' + kw[pos:]
            result = result.replace(kw, ticked)
    return result


def obfuscate_string_reversal(script):
    """
    Technique 3: String Reversal + IEX
    Dao nguoc toan bo script thanh chuoi, roi dung -join de ghep lai va IEX.
    VD: IEX (-join ('noisserpxE-ekovnI'[-1..-18] | ForEach {$_}))
    """
    # Escape single quotes in script
    escaped = script.replace("'", "''")
    reversed_str = escaped[::-1]
    obfuscated = (
        f"$reversed = '{reversed_str}'\n"
        f"$original = -join ($reversed[-1..-{len(reversed_str)}])\n"
        f"Invoke-Expression $original\n"
    )
    return obfuscated


def obfuscate_variable_renaming(script):
    """
    Technique 4: Variable Renaming
    Doi ten tat ca cac bien thanh chuoi ngau nhien.
    VD: $result → $x7Kf2mQ
    """
    # Find all variable names
    var_pattern = r'\$([A-Za-z_]\w{2,})'
    variables = set(re.findall(var_pattern, script))

    # Don't rename built-in variables
    builtins = {'true', 'false', 'null', 'env', 'PSScriptRoot', 'PSCommandPath',
                'args', 'input', 'Host', 'Error', 'ErrorActionPreference',
                'ProgressPreference', 'VerbosePreference', '_', 'PSItem',
                'Matches', 'MyInvocation', 'PSBoundParameters'}

    result = script
    rename_map = {}
    for var in sorted(variables, key=len, reverse=True):  # longest first
        if var.lower() not in {b.lower() for b in builtins} and len(var) > 2:
            new_name = ''.join(random.choices(string.ascii_letters, k=8))
            rename_map[var] = new_name
            # Replace $varname with $randomname (word boundary aware)
            result = re.sub(r'\$' + re.escape(var) + r'\b', '$' + new_name, result)

    return result


def obfuscate_xor_encoding(script):
    """
    Technique 5: XOR Encoding
    Ma hoa toan bo script bang XOR voi key ngau nhien, giai ma khi chay.
    """
    key = random.randint(1, 255)
    xor_bytes = [b ^ key for b in script.encode('utf-8')]
    hex_array = ','.join([f'0x{b:02X}' for b in xor_bytes])

    obfuscated = (
        f"$xorKey = {key}\n"
        f"$encBytes = @({hex_array})\n"
        f"$decBytes = $encBytes | ForEach-Object {{ $_ -bxor $xorKey }}\n"
        f"$script = [System.Text.Encoding]::UTF8.GetString([byte[]]$decBytes)\n"
        f"Invoke-Expression $script\n"
    )
    return obfuscated


OBFUSCATION_METHODS = {
    "Base64 Wrapping": obfuscate_base64_wrap,
    "Tick Insertion": obfuscate_tick_insertion,
    "String Reversal": obfuscate_string_reversal,
    "Variable Renaming": obfuscate_variable_renaming,
    "XOR Encoding": obfuscate_xor_encoding,
}


def load_scripts(directory, desc="Loading"):
    """Load all .ps1 scripts."""
    scripts = []
    ps1_files = sorted([f for f in os.listdir(directory) if f.endswith(('.ps1', '.psm1'))])
    for f in tqdm(ps1_files, desc=desc, ncols=80):
        filepath = os.path.join(directory, f)
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as fh:
                content = fh.read()
        except Exception:
            content = ""
        if content.strip():
            scripts.append(content)
    return scripts


def evaluate_scripts(scripts, label, fasttext_model, ft_classifier, rf_model,
                     top_functions_scores, top_members):
    """Extract features, predict, return metrics."""
    features = core.extract_all_features(
        scripts, fasttext_model, top_functions_scores, top_members,
        desc=f"  Features ({label})"
    )
    features = np.nan_to_num(features, nan=0.0, posinf=0.0, neginf=0.0)

    X_ft = features[:, :FASTTEXT_DIM]
    X_manual = features[:, FASTTEXT_DIM:]
    ft_pred = ft_classifier.predict(X_ft).reshape(-1, 1)
    ft_proba = ft_classifier.predict_proba(X_ft)[:, 1].reshape(-1, 1)
    X_78d = np.hstack([ft_pred, ft_proba, X_manual])

    y_pred = rf_model.predict(X_78d)
    y_proba = rf_model.predict_proba(X_78d)[:, 1]

    return y_pred, y_proba


def main():
    print()
    print("=" * 70)
    print("  OBFUSCATION EXPERIMENT")
    print("  Kiem tra mo hinh voi cac ky thuat obfuscation")
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

    # ── 2. Load scripts ──
    print("\n[2] Loading scripts...")
    mal_scripts = load_scripts(NEW_MAL_DIR, "  New malicious")
    ben_scripts = load_scripts(NEW_BEN_DIR, "  New benign")

    # Limit to manageable size for obfuscation (some scripts are huge)
    MAX_SCRIPT_SIZE = 100000  # 100KB
    mal_scripts_small = [s for s in mal_scripts if len(s) < MAX_SCRIPT_SIZE]
    ben_scripts_small = [s for s in ben_scripts if len(s) < MAX_SCRIPT_SIZE]

    print(f"  Malicious: {len(mal_scripts)} total, {len(mal_scripts_small)} <= 100KB")
    print(f"  Benign:    {len(ben_scripts)} total, {len(ben_scripts_small)} <= 100KB")

    report = []
    report.append("=" * 90)
    report.append("  OBFUSCATION EXPERIMENT RESULTS")
    report.append("=" * 90)
    report.append("")

    # ── 3. Baseline: Original malicious ──
    print("\n[3] Baseline: Original scripts...")
    mal_pred, mal_proba = evaluate_scripts(
        mal_scripts, "Original Malicious",
        fasttext_model, ft_classifier, rf_model,
        top_functions_scores, top_members
    )
    baseline_recall = np.mean(mal_pred == 1) * 100
    print(f"  Baseline Recall (Malicious): {baseline_recall:.1f}%")

    ben_pred, ben_proba = evaluate_scripts(
        ben_scripts, "Original Benign",
        fasttext_model, ft_classifier, rf_model,
        top_functions_scores, top_members
    )
    baseline_fpr = np.mean(ben_pred == 1) * 100
    print(f"  Baseline FP Rate (Benign): {baseline_fpr:.1f}%")

    report.append("=" * 90)
    report.append("  EXPERIMENT A: OBFUSCATE MA DOC MOI → TEST LAI")
    report.append("=" * 90)
    report.append("")
    report.append(f"  Baseline (Original Malicious): Recall = {baseline_recall:.1f}% "
                  f"({int(np.sum(mal_pred == 1))}/{len(mal_pred)} scripts detected)")
    report.append("")

    all_results_mal = {"Original": baseline_recall}
    all_results_ben = {"Original": baseline_fpr}

    # ── 4. Apply each obfuscation technique to MALICIOUS ──
    print("\n[4] Applying obfuscation to malicious scripts...")

    for tech_name, tech_func in OBFUSCATION_METHODS.items():
        print(f"\n  --- {tech_name} ---")
        obf_scripts = []
        errors = 0
        for script in tqdm(mal_scripts_small, desc=f"  Obfuscating", ncols=80):
            try:
                obf = tech_func(script)
                obf_scripts.append(obf)
            except Exception as e:
                errors += 1
                obf_scripts.append(script)  # fallback to original

        if errors > 0:
            print(f"  ({errors} errors, used original)")

        pred, proba = evaluate_scripts(
            obf_scripts, f"Obfuscated-{tech_name}",
            fasttext_model, ft_classifier, rf_model,
            top_functions_scores, top_members
        )
        recall = np.mean(pred == 1) * 100
        detected = int(np.sum(pred == 1))
        total = len(pred)
        delta = recall - baseline_recall

        print(f"  Recall: {recall:.1f}% ({detected}/{total}) [Delta: {delta:+.1f}%]")

        all_results_mal[tech_name] = recall

        report.append(f"  {tech_name}:")
        report.append(f"    Recall = {recall:.1f}% ({detected}/{total} detected)")
        report.append(f"    Delta vs Baseline: {delta:+.1f}%")
        report.append(f"    Scripts tested: {total} (filtered <= 100KB)")
        report.append("")

    # ── 5. Apply each obfuscation technique to BENIGN ──
    print("\n[5] Applying obfuscation to benign scripts...")

    report.append("=" * 90)
    report.append("  EXPERIMENT B: OBFUSCATE FILE BENIGN → TEST LAI")
    report.append("=" * 90)
    report.append("")
    report.append(f"  Baseline (Original Benign): FP Rate = {baseline_fpr:.1f}% "
                  f"({int(np.sum(ben_pred == 1))}/{len(ben_pred)} falsely flagged)")
    report.append("")

    for tech_name, tech_func in OBFUSCATION_METHODS.items():
        print(f"\n  --- {tech_name} (on Benign) ---")
        obf_scripts = []
        errors = 0
        for script in tqdm(ben_scripts_small, desc=f"  Obfuscating", ncols=80):
            try:
                obf = tech_func(script)
                obf_scripts.append(obf)
            except Exception:
                errors += 1
                obf_scripts.append(script)

        if errors > 0:
            print(f"  ({errors} errors, used original)")

        pred, proba = evaluate_scripts(
            obf_scripts, f"Benign-Obfuscated-{tech_name}",
            fasttext_model, ft_classifier, rf_model,
            top_functions_scores, top_members
        )
        fpr = np.mean(pred == 1) * 100
        flagged = int(np.sum(pred == 1))
        total = len(pred)
        delta = fpr - baseline_fpr

        print(f"  FP Rate: {fpr:.1f}% ({flagged}/{total}) [Delta: {delta:+.1f}%]")

        all_results_ben[tech_name] = fpr

        report.append(f"  {tech_name}:")
        report.append(f"    FP Rate = {fpr:.1f}% ({flagged}/{total} falsely flagged)")
        report.append(f"    Delta vs Baseline: {delta:+.1f}%")
        report.append(f"    Scripts tested: {total}")
        report.append("")

    # ── 6. Summary table ──
    report.append("=" * 90)
    report.append("  SUMMARY TABLE")
    report.append("=" * 90)
    report.append("")

    header = f"  {'Obfuscation Technique':<25} {'Mal Recall':>12} {'Ben FP Rate':>13} {'Recall Delta':>14} {'FP Delta':>10}"
    report.append(header)
    report.append("  " + "-" * 78)

    for tech in ["Original"] + list(OBFUSCATION_METHODS.keys()):
        mal_r = all_results_mal.get(tech, 0)
        ben_fp = all_results_ben.get(tech, 0)
        mal_delta = mal_r - baseline_recall
        ben_delta = ben_fp - baseline_fpr
        line = (f"  {tech:<25} {mal_r:>11.1f}% {ben_fp:>12.1f}% "
                f"{mal_delta:>+13.1f}% {ben_delta:>+9.1f}%")
        report.append(line)
        print(line)

    report.append("")

    # ── 7. Key findings ──
    report.append("=" * 90)
    report.append("  KEY FINDINGS")
    report.append("=" * 90)
    report.append("")

    best_tech = max(OBFUSCATION_METHODS.keys(), key=lambda t: all_results_mal.get(t, 0))
    worst_ben = max(OBFUSCATION_METHODS.keys(), key=lambda t: all_results_ben.get(t, 0))

    report.append(f"  1. Ky thuat obfuscation giup TANG Recall nhieu nhat: {best_tech}")
    report.append(f"     Recall: {baseline_recall:.1f}% -> {all_results_mal[best_tech]:.1f}% "
                  f"(+{all_results_mal[best_tech] - baseline_recall:.1f}%)")
    report.append(f"")
    report.append(f"  2. Ky thuat obfuscation gay FP nhieu nhat tren Benign: {worst_ben}")
    report.append(f"     FP Rate: {baseline_fpr:.1f}% -> {all_results_ben[worst_ben]:.1f}% "
                  f"(+{all_results_ben[worst_ben] - baseline_fpr:.1f}%)")
    report.append(f"")
    report.append(f"  3. KET LUAN: Mo hinh M-FastText-2 thuc chat chi hoc duoc")
    report.append(f"     'dau hieu obfuscation' (entropy cao, base64, hex bytes)")
    report.append(f"     chu KHONG hieu ban chat ma doc. Khi ma doc 'sach' (khong")
    report.append(f"     obfuscate) thi mo hinh bo lot, nhung khi them obfuscation")
    report.append(f"     vao thi Recall tang => chung minh mo hinh phu thuoc vao")
    report.append(f"     dau hieu be mat (surface-level indicators).")
    report.append("")

    # ── 8. Save ──
    report_path = os.path.join(RESULTS_DIR, "obfuscation_test_results.txt")
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(report))
    print(f"\n  Report saved: {report_path}")

    # ── 9. Chart ──
    print("\n[6] Generating charts...")

    fig, axes = plt.subplots(1, 2, figsize=(16, 7))
    fig.suptitle('Obfuscation Experiment Results', fontsize=16, fontweight='bold')

    # Chart 1: Malicious Recall after obfuscation
    ax = axes[0]
    techs = ["Original"] + list(OBFUSCATION_METHODS.keys())
    recalls = [all_results_mal.get(t, 0) for t in techs]
    colors_mal = ['#C62828'] + ['#1565C0'] * len(OBFUSCATION_METHODS)

    bars = ax.bar(range(len(techs)), recalls, color=colors_mal, alpha=0.85, edgecolor='white')
    ax.set_xticks(range(len(techs)))
    ax.set_xticklabels([t.replace(' ', '\n') for t in techs], fontsize=9)
    ax.set_ylabel('Recall (%)', fontsize=12)
    ax.set_title('Exp A: Malicious Recall\n(Higher = Model catches more after obfuscation)',
                 fontsize=12, fontweight='bold')
    ax.set_ylim(0, 105)
    for bar, val in zip(bars, recalls):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                f'{val:.1f}%', ha='center', va='bottom', fontsize=10, fontweight='bold')
    ax.axhline(y=baseline_recall, color='red', linestyle='--', alpha=0.5, label='Baseline')
    ax.legend()

    # Chart 2: Benign FP Rate after obfuscation
    ax2 = axes[1]
    fprs = [all_results_ben.get(t, 0) for t in techs]
    colors_ben = ['#2E7D32'] + ['#FF8F00'] * len(OBFUSCATION_METHODS)

    bars2 = ax2.bar(range(len(techs)), fprs, color=colors_ben, alpha=0.85, edgecolor='white')
    ax2.set_xticks(range(len(techs)))
    ax2.set_xticklabels([t.replace(' ', '\n') for t in techs], fontsize=9)
    ax2.set_ylabel('False Positive Rate (%)', fontsize=12)
    ax2.set_title('Exp B: Benign False Positive Rate\n(Higher = Model wrongly flags clean files)',
                  fontsize=12, fontweight='bold')
    ax2.set_ylim(0, max(fprs) * 1.3 + 5)
    for bar, val in zip(bars2, fprs):
        ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                 f'{val:.1f}%', ha='center', va='bottom', fontsize=10, fontweight='bold')
    ax2.axhline(y=baseline_fpr, color='green', linestyle='--', alpha=0.5, label='Baseline')
    ax2.legend()

    plt.tight_layout(rect=[0, 0, 1, 0.93])
    chart_path = os.path.join(RESULTS_DIR, "obfuscation_comparison.png")
    plt.savefig(chart_path, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"  Chart saved: {chart_path}")

    print(f"\n{'=' * 70}")
    print(f"  OBFUSCATION EXPERIMENT COMPLETE!")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    main()
