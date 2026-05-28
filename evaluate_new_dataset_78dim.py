"""
================================================================================
Phần C: Đánh giá mô hình M-FastText-2 trên tập dữ liệu mới
================================================================================
Script này load mô hình đã train (từ m_fasttext2_model.py) và đánh giá
trên tập dữ liệu mới thu thập từ collect_new_dataset.py.

Quy trình:
  1. Load FastText model, Random Forest classifier, và Token config
  2. Load tập dữ liệu mới (new_dataset/malicious + new_dataset/benign)
  3. Trích xuất đặc trưng (574 dim) cho mỗi script mới
  4. Dự đoán (predict) bằng mô hình đã train
  5. Đánh giá kết quả (Accuracy, Precision, Recall, F1, Confusion Matrix)
  6. Xuất biểu đồ và báo cáo

Mục đích: Kiểm tra khả năng tổng quát hóa (generalization) của mô hình
khi áp dụng lên dữ liệu hoàn toàn mới, chưa từng thấy trong quá trình
huấn luyện.
================================================================================
"""

import os
import sys
import json
import pickle
import time
import numpy as np
import warnings
warnings.filterwarnings('ignore')

try:
    from tqdm import tqdm
except ImportError:
    def tqdm(iterable, desc="", ncols=80, **kwargs):
        print(f"  {desc}...")
        return iterable

from gensim.models import FastText as GensimFastText
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_curve, auc
)

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns

# Import feature extraction functions from main model
import m_fasttext2_model_78dim as core

# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(BASE_DIR, "results", "78dim")
NEW_DATASET_DIR = os.path.join(BASE_DIR, "new_dataset")
NEW_MAL_DIR = os.path.join(NEW_DATASET_DIR, "malicious")
NEW_BEN_DIR = os.path.join(NEW_DATASET_DIR, "benign")


# ============================================================
# LOAD SAVED MODEL
# ============================================================

def load_saved_model():
    """Load the pre-trained FastText model, RF classifier, and token config."""
    
    print("\n[1] Loading saved model files...")
    
    # Load FastText model
    ft_path = os.path.join(RESULTS_DIR, "m_fasttext2.model")
    if not os.path.exists(ft_path):
        print(f"  [ERROR] FastText model not found: {ft_path}")
        print(f"  Please run m_fasttext2_model.py first!")
        sys.exit(1)
    
    fasttext_model = GensimFastText.load(ft_path)
    print(f"  [OK] FastText model loaded (vocab: {len(fasttext_model.wv)} words)")
    
    # Load Random Forest classifier
    rf_path = os.path.join(RESULTS_DIR, "rf_classifier.pkl")
    if not os.path.exists(rf_path):
        print(f"  [ERROR] RF classifier not found: {rf_path}")
        sys.exit(1)
    
    with open(rf_path, 'rb') as f:
        rf_model = pickle.load(f)
    print(f"  [OK] Random Forest classifier loaded "
          f"(trees: {rf_model.n_estimators})")
    
    # Load simulated FastText Logistic Regression model
    ft_clf_path = os.path.join(RESULTS_DIR, "ft_classifier.pkl")
    if not os.path.exists(ft_clf_path):
        print(f"  [ERROR] FT classifier not found: {ft_clf_path}")
        sys.exit(1)
    with open(ft_clf_path, 'rb') as f:
        ft_model = pickle.load(f)
    print(f"  [OK] Simulated FastText Classifier loaded")
    
    # Load token config
    tokens_path = os.path.join(RESULTS_DIR, "top_tokens_78dim.json")
    if not os.path.exists(tokens_path):
        print(f"  [ERROR] Token config not found: {tokens_path}")
        sys.exit(1)
    
    with open(tokens_path, 'r') as f:
        token_config = json.load(f)
    
    top_functions_scores = token_config["top_functions_scores"]
    top_members = token_config["top_members"]
    print(f"  [OK] Token config loaded")
    
    return fasttext_model, ft_model, rf_model, top_functions_scores, top_members


# ============================================================
# LOAD NEW DATASET
# ============================================================

def load_new_dataset():
    """Load the new dataset collected by collect_new_dataset.py."""
    
    print("\n[2] Loading new dataset...")
    
    if not os.path.exists(NEW_DATASET_DIR):
        print(f"  [ERROR] New dataset not found: {NEW_DATASET_DIR}")
        print(f"  Please run collect_new_dataset.py first!")
        sys.exit(1)
    
    # Load malicious scripts
    mal_scripts, mal_files = core.load_scripts(
        NEW_MAL_DIR, "  Loading new malicious"
    )
    
    # Load benign scripts
    ben_scripts, ben_files = core.load_scripts(
        NEW_BEN_DIR, "  Loading new benign"
    )
    
    # Filter empty
    mal_scripts_clean = [s for s in mal_scripts if len(s.strip()) > 0]
    ben_scripts_clean = [s for s in ben_scripts if len(s.strip()) > 0]
    
    print(f"\n  New Dataset Summary:")
    print(f"    Malicious: {len(mal_scripts_clean)} scripts")
    print(f"    Benign:    {len(ben_scripts_clean)} scripts")
    print(f"    Total:     {len(mal_scripts_clean) + len(ben_scripts_clean)} scripts")
    
    return mal_scripts_clean, ben_scripts_clean


# ============================================================
# EVALUATE ON NEW DATA
# ============================================================

def evaluate(fasttext_model, ft_model, rf_model, top_functions_scores, top_members,
             mal_scripts, ben_scripts):
    """
    Evaluate the trained model on the new dataset.
    Uses the saved model to predict labels, then compares with ground truth.
    """
    
    # Extract features for new data
    print("\n[3] Extracting features from new dataset...")
    
    mal_features = core.extract_all_features(
        mal_scripts, fasttext_model, top_functions_scores, top_members,
        desc="  Features (new malicious)"
    )
    ben_features = core.extract_all_features(
        ben_scripts, fasttext_model, top_functions_scores, top_members,
        desc="  Features (new benign)"
    )
    
    X_new = np.vstack([mal_features, ben_features])
    y_true = np.array([1] * len(mal_features) + [0] * len(ben_features))
    
    # Clean NaN/Inf
    X_new = np.nan_to_num(X_new, nan=0.0, posinf=0.0, neginf=0.0)
    
    # Convert 376D to 78D using the ft_model
    X_new_ft = X_new[:, :core.FASTTEXT_DIM]
    X_new_manual = X_new[:, core.FASTTEXT_DIM:]
    y_new_ft_pred = ft_model.predict(X_new_ft).reshape(-1, 1)
    y_new_ft_proba = ft_model.predict_proba(X_new_ft)[:, 1].reshape(-1, 1)
    X_new_final = np.hstack([y_new_ft_pred, y_new_ft_proba, X_new_manual])
    
    print(f"  Extracted feature matrix shape: {X_new.shape}")
    print(f"  Final 78D feature matrix shape: {X_new_final.shape}")
    
    # Predict
    print("\n[4] Predicting with trained model...")
    y_pred = rf_model.predict(X_new_final)
    y_proba = rf_model.predict_proba(X_new_final)[:, 1]
    
    # Metrics
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    cm = confusion_matrix(y_true, y_pred)
    
    print(f"\n{'=' * 65}")
    print(f"  EVALUATION RESULTS ON NEW DATASET")
    print(f"{'=' * 65}")
    print(f"  Total samples:  {len(y_true)}")
    print(f"  Malicious:      {sum(y_true == 1)}")
    print(f"  Benign:         {sum(y_true == 0)}")
    print(f"\n  ┌───────────────────┬────────────┐")
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
    
    print(f"\n  Classification Report:")
    report = classification_report(
        y_true, y_pred,
        target_names=['Benign', 'Malicious'],
        digits=4
    )
    for line in report.split('\n'):
        print(f"  {line}")
    
    return {
        'accuracy': acc, 'precision': prec,
        'recall': rec, 'f1': f1,
        'y_true': y_true, 'y_pred': y_pred,
        'y_proba': y_proba, 'cm': cm,
    }


# ============================================================
# VISUALIZATION
# ============================================================

def generate_visualizations(results):
    """Generate confusion matrix and ROC curve for the new dataset evaluation."""
    
    print("\n[5] Generating visualizations...")
    
    plt.rcParams.update({
        'font.size': 12,
        'axes.labelsize': 13,
        'axes.titlesize': 14,
        'figure.facecolor': 'white',
    })
    
    # ── Confusion Matrix ──
    fig, ax = plt.subplots(figsize=(7, 6))
    sns.heatmap(
        results['cm'], annot=True, fmt='d', cmap='Oranges',
        xticklabels=['Benign', 'Malicious'],
        yticklabels=['Benign', 'Malicious'],
        annot_kws={'size': 16, 'weight': 'bold'},
        linewidths=0.5, linecolor='white',
        ax=ax,
    )
    ax.set_xlabel('Predicted Label', fontsize=13)
    ax.set_ylabel('True Label', fontsize=13)
    ax.set_title('Confusion Matrix\nNew Dataset (Generalization Test)',
                 fontsize=14, fontweight='bold')
    
    total = results['cm'].sum()
    correct = results['cm'][0, 0] + results['cm'][1, 1]
    acc_pct = correct / total * 100
    ax.text(0.5, -0.15, f'Accuracy: {acc_pct:.2f}%',
            transform=ax.transAxes, ha='center', fontsize=12,
            style='italic', color='#333333')
    
    plt.tight_layout()
    cm_path = os.path.join(RESULTS_DIR, "confusion_matrix_new_dataset.png")
    plt.savefig(cm_path, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"  [OK] Saved: {os.path.basename(cm_path)}")
    
    # ── ROC Curve ──
    fpr, tpr, _ = roc_curve(results['y_true'], results['y_proba'])
    roc_auc = auc(fpr, tpr)
    
    fig, ax = plt.subplots(figsize=(8, 6))
    ax.plot(fpr, tpr, color='#E65100', lw=2.5,
            label=f'New Dataset (AUC = {roc_auc:.4f})')
    ax.plot([0, 1], [0, 1], color='#BDBDBD', lw=1.5, linestyle='--',
            label='Random Classifier (AUC = 0.5000)')
    ax.fill_between(fpr, tpr, alpha=0.08, color='#E65100')
    
    ax.set_xlabel('False Positive Rate (FPR)', fontsize=13)
    ax.set_ylabel('True Positive Rate (TPR)', fontsize=13)
    ax.set_title('ROC Curve\nNew Dataset (Generalization Test)',
                 fontsize=14, fontweight='bold')
    ax.legend(loc='lower right', fontsize=11, framealpha=0.9)
    ax.set_xlim([-0.02, 1.02])
    ax.set_ylim([-0.02, 1.02])
    
    plt.tight_layout()
    roc_path = os.path.join(RESULTS_DIR, "roc_curve_new_dataset.png")
    plt.savefig(roc_path, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"  [OK] Saved: {os.path.basename(roc_path)}")
    
    # ── Comparison with original results ──
    fig, ax = plt.subplots(figsize=(10, 6))
    
    metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
    new_vals = [
        results['accuracy'], results['precision'],
        results['recall'], results['f1']
    ]
    # Paper's reported values for reference
    paper_original = [0.9893, 0.9779, 0.9767, 0.9773]
    paper_mixed = [0.9776, 0.9779, 0.9767, 0.9773]
    
    x = np.arange(len(metrics))
    width = 0.25
    
    bars1 = ax.bar(x - width, paper_original, width,
                   label='Paper: Original Dataset',
                   color='#1565C0', alpha=0.85, edgecolor='white')
    bars2 = ax.bar(x, paper_mixed, width,
                   label='Paper: Mixed Dataset',
                   color='#FF8F00', alpha=0.85, edgecolor='white')
    bars3 = ax.bar(x + width, new_vals, width,
                   label='NEW Dataset (Ours)',
                   color='#2E7D32', alpha=0.85, edgecolor='white')
    
    ax.set_ylabel('Score', fontsize=13)
    ax.set_title('M-FastText-2 Performance: Paper vs New Dataset',
                 fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(metrics, fontsize=12)
    ax.legend(fontsize=10, loc='lower left')
    
    all_vals = new_vals + paper_original + paper_mixed
    y_min = max(0, min(all_vals) - 0.08)
    ax.set_ylim(y_min, 1.02)
    
    for bar in bars3:
        h = bar.get_height()
        ax.annotate(f'{h:.4f}',
                    xy=(bar.get_x() + bar.get_width() / 2, h),
                    xytext=(0, 4), textcoords="offset points",
                    ha='center', va='bottom', fontsize=9, fontweight='bold')
    
    plt.tight_layout()
    comp_path = os.path.join(RESULTS_DIR, "comparison_new_dataset.png")
    plt.savefig(comp_path, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"  [OK] Saved: {os.path.basename(comp_path)}")
    
    return roc_auc


# ============================================================
# MAIN
# ============================================================

def main():
    print()
    print("=" * 65)
    print("  PART C: Evaluate M-FastText-2 on NEW Dataset")
    print("  Testing generalization capability of the trained model")
    print("=" * 65)
    
    start_time = time.time()
    
    # Step 1: Load model
    fasttext_model, ft_model, rf_model, top_functions_scores, top_members = load_saved_model()
    
    # Step 2: Load new data
    mal_scripts, ben_scripts = load_new_dataset()
    
    if len(mal_scripts) == 0 or len(ben_scripts) == 0:
        print("\n  [ERROR] New dataset is empty!")
        print("  Please run collect_new_dataset.py first.")
        sys.exit(1)
    
    # Step 3-4: Evaluate
    results = evaluate(
        fasttext_model, ft_model, rf_model,
        top_functions_scores, top_members,
        mal_scripts, ben_scripts
    )
    
    # Step 5: Visualize
    roc_auc = generate_visualizations(results)
    
    elapsed = time.time() - start_time
    
    # Summary
    print(f"\n{'=' * 65}")
    print(f"  FINAL SUMMARY")
    print(f"{'=' * 65}")
    print(f"\n  The model trained on the MPSD dataset was evaluated on a")
    print(f"  completely new dataset from different sources.")
    print(f"\n  Key results:")
    print(f"    Accuracy:  {results['accuracy']:.4f} "
          f"({results['accuracy']*100:.2f}%)")
    print(f"    AUC:       {roc_auc:.4f}")
    print(f"    F1-Score:  {results['f1']:.4f}")
    print(f"\n  Execution time: {elapsed:.1f}s")
    print(f"  New visualizations saved to: {RESULTS_DIR}")
    print(f"{'=' * 65}")


if __name__ == "__main__":
    main()
