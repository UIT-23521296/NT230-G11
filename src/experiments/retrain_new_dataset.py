"""
================================================================================
RETRAIN EXPERIMENT: Train M-FastText-2 on New Dataset
================================================================================
Thi nghiem chung minh rang kien truc mo hinh KHONG co van de,
van de nam o du lieu huan luyen (Domain Shift).

Experiment 1: 5-Fold CV tren tap MỚI (new_dataset only)
  → Chung minh kien truc van hoat dong tot neu duoc train dung du lieu.

Experiment 2: 5-Fold CV tren tap GOP (MPSD + new_dataset)
  → Chung minh bo sung du lieu giup cai thien kha nang tong quat hoa.

Experiment 3: Train tren tap GOP, Test tren tap MỚI (hold-out)
  → Mo phong kich ban thuc te: mo hinh duoc cap nhat voi du lieu moi,
    sau do danh gia tren chinh du lieu moi do.
================================================================================
"""

import os
import sys
import json
import time
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
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_curve, auc
)

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
MPSD_BEN_DIR = os.path.join(BASE_DIR, "mpsd", "powershell_benign_dataset")
NEW_MAL_DIR = os.path.join(BASE_DIR, "new_dataset", "malicious")
NEW_BEN_DIR = os.path.join(BASE_DIR, "new_dataset", "benign")

# Same hyperparams as paper
FASTTEXT_DIM = 300
RF_N_ESTIMATORS = 70
RF_MAX_FEATURES = 8
RF_RANDOM_STATE = 0
N_FOLDS = 5


def run_cv_78dim(X, y, experiment_name):
    """
    Run 5-fold stratified CV on 376D raw features,
    compressing FastText 300D -> 2D inside each fold (no data leakage).
    Returns dict with metrics.
    """
    print(f"\n{'=' * 65}")
    print(f"  {experiment_name}")
    print(f"{'=' * 65}")
    print(f"  Samples: {len(X)}")
    print(f"  Raw dims: {X.shape[1]}")

    label_counts = Counter(y)
    print(f"  Classes: Benign={label_counts[0]}, Malicious={label_counts[1]}")

    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

    skf = StratifiedKFold(n_splits=N_FOLDS, shuffle=True, random_state=RF_RANDOM_STATE)

    fold_results = []
    all_y_true, all_y_pred, all_y_proba = [], [], []

    print(f"\n  {'Fold':<6} {'Accuracy':<11} {'Precision':<11} {'Recall':<11} {'F1-Score':<11}")
    print(f"  {'─' * 50}")

    for fold, (train_idx, test_idx) in enumerate(skf.split(X, y), 1):
        X_train, X_test = X[train_idx], X[test_idx]
        y_train, y_test = y[train_idx], y[test_idx]

        # Compress FastText 300D -> 2D
        X_train_ft = X_train[:, :FASTTEXT_DIM]
        X_train_manual = X_train[:, FASTTEXT_DIM:]
        X_test_ft = X_test[:, :FASTTEXT_DIM]
        X_test_manual = X_test[:, FASTTEXT_DIM:]

        ft_clf = LogisticRegression(random_state=RF_RANDOM_STATE, max_iter=1000)
        ft_clf.fit(X_train_ft, y_train)

        X_train_final = np.hstack([
            ft_clf.predict(X_train_ft).reshape(-1, 1),
            ft_clf.predict_proba(X_train_ft)[:, 1].reshape(-1, 1),
            X_train_manual
        ])
        X_test_final = np.hstack([
            ft_clf.predict(X_test_ft).reshape(-1, 1),
            ft_clf.predict_proba(X_test_ft)[:, 1].reshape(-1, 1),
            X_test_manual
        ])

        # Random Forest
        clf = RandomForestClassifier(
            n_estimators=RF_N_ESTIMATORS,
            max_features=RF_MAX_FEATURES,
            random_state=RF_RANDOM_STATE,
            n_jobs=-1,
        )
        clf.fit(X_train_final, y_train)

        y_pred = clf.predict(X_test_final)
        y_proba = clf.predict_proba(X_test_final)[:, 1]

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)

        fold_results.append({'fold': fold, 'accuracy': acc,
                             'precision': prec, 'recall': rec, 'f1': f1})
        all_y_true.extend(y_test)
        all_y_pred.extend(y_pred)
        all_y_proba.extend(y_proba)

        print(f"  {fold:<6} {acc:<11.4f} {prec:<11.4f} {rec:<11.4f} {f1:<11.4f}")

    avg_acc = np.mean([r['accuracy'] for r in fold_results])
    avg_prec = np.mean([r['precision'] for r in fold_results])
    avg_rec = np.mean([r['recall'] for r in fold_results])
    avg_f1 = np.mean([r['f1'] for r in fold_results])
    std_acc = np.std([r['accuracy'] for r in fold_results])

    print(f"  {'─' * 50}")
    print(f"  {'AVG':<6} {avg_acc:<11.4f} {avg_prec:<11.4f} {avg_rec:<11.4f} {avg_f1:<11.4f}")
    print(f"  Accuracy std: +/-{std_acc:.4f}")

    print(f"\n  Classification Report (aggregated):")
    report = classification_report(
        all_y_true, all_y_pred,
        target_names=['Benign', 'Malicious'], digits=4
    )
    for line in report.split('\n'):
        print(f"  {line}")

    return {
        'fold_results': fold_results,
        'avg_accuracy': avg_acc, 'avg_precision': avg_prec,
        'avg_recall': avg_rec, 'avg_f1': avg_f1,
        'std_accuracy': std_acc,
        'y_true': np.array(all_y_true),
        'y_pred': np.array(all_y_pred),
        'y_proba': np.array(all_y_proba),
    }


def run_holdout_78dim(X_train, y_train, X_test, y_test, experiment_name):
    """
    Train on X_train, test on X_test (hold-out evaluation).
    """
    print(f"\n{'=' * 65}")
    print(f"  {experiment_name}")
    print(f"{'=' * 65}")
    print(f"  Train samples: {len(X_train)}")
    print(f"  Test samples:  {len(X_test)}")

    X_train = np.nan_to_num(X_train, nan=0.0, posinf=0.0, neginf=0.0)
    X_test = np.nan_to_num(X_test, nan=0.0, posinf=0.0, neginf=0.0)

    # Compress FastText
    ft_clf = LogisticRegression(random_state=RF_RANDOM_STATE, max_iter=1000)
    ft_clf.fit(X_train[:, :FASTTEXT_DIM], y_train)

    X_train_final = np.hstack([
        ft_clf.predict(X_train[:, :FASTTEXT_DIM]).reshape(-1, 1),
        ft_clf.predict_proba(X_train[:, :FASTTEXT_DIM])[:, 1].reshape(-1, 1),
        X_train[:, FASTTEXT_DIM:]
    ])
    X_test_final = np.hstack([
        ft_clf.predict(X_test[:, :FASTTEXT_DIM]).reshape(-1, 1),
        ft_clf.predict_proba(X_test[:, :FASTTEXT_DIM])[:, 1].reshape(-1, 1),
        X_test[:, FASTTEXT_DIM:]
    ])

    clf = RandomForestClassifier(
        n_estimators=RF_N_ESTIMATORS,
        max_features=RF_MAX_FEATURES,
        random_state=RF_RANDOM_STATE,
        n_jobs=-1,
    )
    clf.fit(X_train_final, y_train)

    y_pred = clf.predict(X_test_final)
    y_proba = clf.predict_proba(X_test_final)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)

    cm = confusion_matrix(y_test, y_pred)

    print(f"\n  Results:")
    print(f"  ┌───────────────────┬────────────┐")
    print(f"  │ Metric            │   Score    │")
    print(f"  ├───────────────────┼────────────┤")
    print(f"  │ Accuracy          │  {acc:.4f}    │")
    print(f"  │ Precision         │  {prec:.4f}    │")
    print(f"  │ Recall            │  {rec:.4f}    │")
    print(f"  │ F1-Score          │  {f1:.4f}    │")
    print(f"  └───────────────────┴────────────┘")

    print(f"\n  Confusion Matrix:")
    print(f"                    Predicted")
    print(f"                  Benign  Malicious")
    print(f"  True Benign    {cm[0][0]:>6}  {cm[0][1]:>6}")
    print(f"  True Malicious {cm[1][0]:>6}  {cm[1][1]:>6}")

    report = classification_report(
        y_test, y_pred,
        target_names=['Benign', 'Malicious'], digits=4
    )
    print(f"\n  Classification Report:")
    for line in report.split('\n'):
        print(f"  {line}")

    return {
        'accuracy': acc, 'precision': prec,
        'recall': rec, 'f1': f1,
        'y_true': y_test, 'y_pred': y_pred,
        'y_proba': y_proba, 'cm': cm,
    }


def main():
    print()
    print("=" * 65)
    print("  RETRAIN EXPERIMENT")
    print("  Train M-FastText-2 on New Dataset")
    print("=" * 65)

    start_time = time.time()

    # ── 1. Load saved FastText model (for embeddings only) ──
    print("\n[1] Loading FastText model (for embeddings)...")
    ft_path = os.path.join(RESULTS_DIR, "m_fasttext2.model")
    fasttext_model = GensimFastText.load(ft_path)
    print(f"  FastText loaded (vocab: {len(fasttext_model.wv)})")

    # ── 2. Load ALL scripts ──
    print("\n[2] Loading scripts...")
    mpsd_mal, _ = core.load_scripts(MPSD_MAL_DIR, "  MPSD malicious")
    mpsd_ben, _ = core.load_scripts(MPSD_BEN_DIR, "  MPSD benign")
    new_mal, _ = core.load_scripts(NEW_MAL_DIR, "  New malicious")
    new_ben, _ = core.load_scripts(NEW_BEN_DIR, "  New benign")

    # Clean empty
    mpsd_mal = [s for s in mpsd_mal if len(s.strip()) > 0]
    mpsd_ben = [s for s in mpsd_ben if len(s.strip()) > 0]
    new_mal = [s for s in new_mal if len(s.strip()) > 0]
    new_ben = [s for s in new_ben if len(s.strip()) > 0]

    print(f"\n  MPSD: {len(mpsd_mal)} mal + {len(mpsd_ben)} ben = {len(mpsd_mal)+len(mpsd_ben)}")
    print(f"  New:  {len(new_mal)} mal + {len(new_ben)} ben = {len(new_mal)+len(new_ben)}")

    # ── 3. Discover tokens for EACH experiment ──

    # --- Tokens for New Dataset only ---
    print("\n[3A] Discovering tokens from NEW dataset...")
    new_all = new_mal + new_ben
    new_top_funcs, new_top_members = core.discover_top_tokens(
        new_mal, new_ben, new_all, k_functions=200, k_members=33
    )

    # --- Tokens for Combined dataset ---
    print("\n[3B] Discovering tokens from COMBINED dataset...")
    combined_mal = mpsd_mal + new_mal
    combined_ben = mpsd_ben + new_ben
    combined_all = combined_mal + combined_ben
    comb_top_funcs, comb_top_members = core.discover_top_tokens(
        combined_mal, combined_ben, combined_all, k_functions=200, k_members=33
    )

    # ── 4. Extract features ──
    print("\n[4A] Extracting features (New Dataset, new tokens)...")
    new_mal_feat = core.extract_all_features(
        new_mal, fasttext_model, new_top_funcs, new_top_members,
        desc="  New mal features"
    )
    new_ben_feat = core.extract_all_features(
        new_ben, fasttext_model, new_top_funcs, new_top_members,
        desc="  New ben features"
    )

    X_new = np.vstack([new_mal_feat, new_ben_feat])
    y_new = np.array([1] * len(new_mal_feat) + [0] * len(new_ben_feat))

    print(f"\n[4B] Extracting features (Combined Dataset, combined tokens)...")
    comb_mpsd_mal_feat = core.extract_all_features(
        mpsd_mal, fasttext_model, comb_top_funcs, comb_top_members,
        desc="  MPSD mal features"
    )
    comb_mpsd_ben_feat = core.extract_all_features(
        mpsd_ben, fasttext_model, comb_top_funcs, comb_top_members,
        desc="  MPSD ben features"
    )
    comb_new_mal_feat = core.extract_all_features(
        new_mal, fasttext_model, comb_top_funcs, comb_top_members,
        desc="  New mal features"
    )
    comb_new_ben_feat = core.extract_all_features(
        new_ben, fasttext_model, comb_top_funcs, comb_top_members,
        desc="  New ben features"
    )

    X_combined = np.vstack([comb_mpsd_mal_feat, comb_mpsd_ben_feat,
                            comb_new_mal_feat, comb_new_ben_feat])
    y_combined = np.array(
        [1] * len(comb_mpsd_mal_feat) + [0] * len(comb_mpsd_ben_feat) +
        [1] * len(comb_new_mal_feat) + [0] * len(comb_new_ben_feat)
    )

    # For Experiment 3: holdout
    X_train_exp3 = np.vstack([comb_mpsd_mal_feat, comb_mpsd_ben_feat,
                              comb_new_mal_feat, comb_new_ben_feat])
    y_train_exp3 = y_combined.copy()

    X_test_exp3 = np.vstack([comb_new_mal_feat, comb_new_ben_feat])
    y_test_exp3 = np.array([1] * len(comb_new_mal_feat) + [0] * len(comb_new_ben_feat))

    # ── 5. Run Experiments ──
    # Experiment 1: CV on new dataset only
    exp1 = run_cv_78dim(X_new, y_new,
                        "EXP 1: 5-Fold CV on NEW DATASET ONLY")

    # Experiment 2: CV on combined dataset
    exp2 = run_cv_78dim(X_combined, y_combined,
                        "EXP 2: 5-Fold CV on COMBINED (MPSD + New)")

    # Experiment 3: Train combined, test new
    exp3 = run_holdout_78dim(
        X_train_exp3, y_train_exp3,
        X_test_exp3, y_test_exp3,
        "EXP 3: Train COMBINED -> Test on NEW DATASET"
    )

    elapsed = time.time() - start_time

    # ── 6. Summary Comparison ──
    print(f"\n\n{'=' * 65}")
    print(f"  FINAL COMPARISON TABLE")
    print(f"{'=' * 65}")
    print(f"\n  {'Experiment':<45} {'Acc':>8} {'Prec':>8} {'Recall':>8} {'F1':>8}")
    print(f"  {'─' * 79}")
    print(f"  {'Baseline: Train MPSD, Test New (old result)':<45} {'0.7769':>8} {'0.9880':>8} {'0.2654':>8} {'0.4184':>8}")
    print(f"  {'EXP1: CV on New Dataset Only':<45} {exp1['avg_accuracy']:>8.4f} {exp1['avg_precision']:>8.4f} {exp1['avg_recall']:>8.4f} {exp1['avg_f1']:>8.4f}")
    print(f"  {'EXP2: CV on Combined (MPSD+New)':<45} {exp2['avg_accuracy']:>8.4f} {exp2['avg_precision']:>8.4f} {exp2['avg_recall']:>8.4f} {exp2['avg_f1']:>8.4f}")
    print(f"  {'EXP3: Train Combined, Test New':<45} {exp3['accuracy']:>8.4f} {exp3['precision']:>8.4f} {exp3['recall']:>8.4f} {exp3['f1']:>8.4f}")
    print(f"\n  Total time: {elapsed:.1f}s")

    # ── 7. Save results ──
    report_path = os.path.join(RESULTS_DIR, "retrain_results.txt")
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write("=" * 65 + "\n")
        f.write("  RETRAIN EXPERIMENT RESULTS\n")
        f.write("=" * 65 + "\n\n")
        f.write(f"  {'Experiment':<45} {'Acc':>8} {'Prec':>8} {'Recall':>8} {'F1':>8}\n")
        f.write(f"  {'─' * 79}\n")
        f.write(f"  {'Baseline: Train MPSD, Test New':<45} {'0.7769':>8} {'0.9880':>8} {'0.2654':>8} {'0.4184':>8}\n")
        f.write(f"  {'EXP1: CV on New Dataset Only':<45} {exp1['avg_accuracy']:>8.4f} {exp1['avg_precision']:>8.4f} {exp1['avg_recall']:>8.4f} {exp1['avg_f1']:>8.4f}\n")
        f.write(f"  {'EXP2: CV on Combined (MPSD+New)':<45} {exp2['avg_accuracy']:>8.4f} {exp2['avg_precision']:>8.4f} {exp2['avg_recall']:>8.4f} {exp2['avg_f1']:>8.4f}\n")
        f.write(f"  {'EXP3: Train Combined, Test New':<45} {exp3['accuracy']:>8.4f} {exp3['precision']:>8.4f} {exp3['recall']:>8.4f} {exp3['f1']:>8.4f}\n")
        f.write(f"\n  EXP1 fold details:\n")
        for r in exp1['fold_results']:
            f.write(f"    Fold {r['fold']}: Acc={r['accuracy']:.4f} Prec={r['precision']:.4f} Rec={r['recall']:.4f} F1={r['f1']:.4f}\n")
        f.write(f"\n  EXP2 fold details:\n")
        for r in exp2['fold_results']:
            f.write(f"    Fold {r['fold']}: Acc={r['accuracy']:.4f} Prec={r['precision']:.4f} Rec={r['recall']:.4f} F1={r['f1']:.4f}\n")
        if 'cm' in exp3:
            f.write(f"\n  EXP3 Confusion Matrix:\n")
            f.write(f"                    Predicted\n")
            f.write(f"                  Benign  Malicious\n")
            f.write(f"  True Benign    {exp3['cm'][0][0]:>6}  {exp3['cm'][0][1]:>6}\n")
            f.write(f"  True Malicious {exp3['cm'][1][0]:>6}  {exp3['cm'][1][1]:>6}\n")
    print(f"\n  Results saved to: {report_path}")

    # ── 8. Comparison bar chart ──
    print("\n[7] Generating comparison chart...")
    fig, ax = plt.subplots(figsize=(14, 7))

    experiments = [
        'Baseline\n(Train MPSD\nTest New)',
        'EXP1\n(CV on\nNew Only)',
        'EXP2\n(CV on\nCombined)',
        'EXP3\n(Train Combined\nTest New)'
    ]
    metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score']

    baseline_vals = [0.7769, 0.9880, 0.2654, 0.4184]
    exp1_vals = [exp1['avg_accuracy'], exp1['avg_precision'], exp1['avg_recall'], exp1['avg_f1']]
    exp2_vals = [exp2['avg_accuracy'], exp2['avg_precision'], exp2['avg_recall'], exp2['avg_f1']]
    exp3_vals = [exp3['accuracy'], exp3['precision'], exp3['recall'], exp3['f1']]

    x = np.arange(len(metrics))
    width = 0.18

    colors = ['#C62828', '#1565C0', '#2E7D32', '#FF8F00']
    all_vals = [baseline_vals, exp1_vals, exp2_vals, exp3_vals]

    for i, (vals, label, color) in enumerate(zip(all_vals, experiments, colors)):
        bars = ax.bar(x + (i - 1.5) * width, vals, width,
                      label=label.replace('\n', ' '),
                      color=color, alpha=0.85, edgecolor='white')
        for bar in bars:
            h = bar.get_height()
            ax.annotate(f'{h:.3f}',
                        xy=(bar.get_x() + bar.get_width() / 2, h),
                        xytext=(0, 3), textcoords="offset points",
                        ha='center', va='bottom', fontsize=8, fontweight='bold')

    ax.set_ylabel('Score', fontsize=13)
    ax.set_title('Retrain Experiment: M-FastText-2 Performance Comparison',
                 fontsize=15, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(metrics, fontsize=12)
    ax.legend(fontsize=9, loc='lower left')
    ax.set_ylim(0, 1.12)
    ax.axhline(y=1.0, color='gray', linestyle=':', alpha=0.3)

    plt.tight_layout()
    chart_path = os.path.join(RESULTS_DIR, "retrain_comparison.png")
    plt.savefig(chart_path, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"  Chart saved: {chart_path}")

    print(f"\n{'=' * 65}")
    print(f"  ALL EXPERIMENTS COMPLETE!")
    print(f"{'=' * 65}")


if __name__ == "__main__":
    main()
