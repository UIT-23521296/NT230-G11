import os
import sys
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '..', '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.core import m_fasttext2_model_enhanced as core

def setup_plot_style():
    plt.rcParams.update({
        'font.family': 'sans-serif',
        'font.size': 12,
        'axes.labelsize': 13,
        'axes.titlesize': 14,
        'figure.facecolor': 'white',
        'axes.facecolor': 'white',
        'axes.grid': True,
        'grid.alpha': 0.3,
    })

def main():
    print("=================================================================")
    print("  EVALUATING HYBRID MODEL (RULE-BASED + ML)")
    print("=================================================================")
    
    # 1. Load Data
    mpsd_mal_dir = os.path.join(PROJECT_ROOT, "data", "mpsd", "malicious_pure")
    mpsd_ben_dir = os.path.join(PROJECT_ROOT, "data", "mpsd", "powershell_benign_dataset")
    
    new_mal_dir = os.path.join(PROJECT_ROOT, "data", "new_dataset", "malicious")
    new_ben_dir = os.path.join(PROJECT_ROOT, "data", "new_dataset", "benign")
    
    mpsd_mal, _ = core.load_scripts(mpsd_mal_dir, desc="MPSD malicious")
    mpsd_ben, _ = core.load_scripts(mpsd_ben_dir, desc="MPSD benign")
    
    new_mal, _ = core.load_scripts(new_mal_dir, desc="New malicious")
    new_ben, _ = core.load_scripts(new_ben_dir, desc="New benign")
    
    train_scripts = mpsd_mal + mpsd_ben
    y_train = np.array([1]*len(mpsd_mal) + [0]*len(mpsd_ben))
    
    test_scripts = new_mal + new_ben
    y_test = np.array([1]*len(new_mal) + [0]*len(new_ben))
    
    # 2. Extract tokens and train FastText
    top_funcs, top_members = core.discover_top_tokens(mpsd_mal, mpsd_ben, train_scripts)
    ft_model = core.train_fasttext_model(train_scripts)
    
    # 3. Extract Features
    X_train_raw = core.extract_all_features(train_scripts, ft_model, top_funcs, top_members, desc="Train features")
    X_test_raw = core.extract_all_features(test_scripts, ft_model, top_funcs, top_members, desc="Test features")
    
    X_train_raw = np.nan_to_num(X_train_raw, nan=0.0, posinf=0.0, neginf=0.0)
    X_test_raw = np.nan_to_num(X_test_raw, nan=0.0, posinf=0.0, neginf=0.0)
    
    # 4. Dimension Reduction (FastText -> 2D)
    ft_dim = core.FASTTEXT_DIM
    ft_clf = LogisticRegression(random_state=core.RF_RANDOM_STATE, max_iter=1000)
    ft_clf.fit(X_train_raw[:, :ft_dim], y_train)
    
    yt_pred = ft_clf.predict(X_train_raw[:, :ft_dim]).reshape(-1, 1)
    yt_proba = ft_clf.predict_proba(X_train_raw[:, :ft_dim])[:, 1].reshape(-1, 1)
    X_train = np.hstack([yt_pred, yt_proba, X_train_raw[:, ft_dim:]])
    
    yte_pred = ft_clf.predict(X_test_raw[:, :ft_dim]).reshape(-1, 1)
    yte_proba = ft_clf.predict_proba(X_test_raw[:, :ft_dim])[:, 1].reshape(-1, 1)
    X_test = np.hstack([yte_pred, yte_proba, X_test_raw[:, ft_dim:]])
    
    # 5. Train Random Forest (ML Component)
    rf = RandomForestClassifier(
        n_estimators=core.RF_N_ESTIMATORS,
        max_features=core.RF_MAX_FEATURES,
        random_state=core.RF_RANDOM_STATE,
        n_jobs=-1
    )
    rf.fit(X_train, y_train)
    
    # 6. Evaluate Hybrid Engine
    y_pred_ml = rf.predict(X_test)
    y_pred_final = []
    
    # The last 13 dimensions are the Win32 API features
    win32_apis = [
        'VirtualAlloc', 'CreateThread', 'WriteProcessMemory', 'LoadLibrary',
        'GetProcAddress', 'AmsiScanBuffer', 'EtwEventWrite', 'Add-Type',
        'DllImport', 'System.Reflection', 'System.Runtime.InteropServices',
        'Net.Sockets', 'Security.Cryptography'
    ]
    
    num_win32_features = len(win32_apis)
    win32_idx_start = X_test.shape[1] - num_win32_features
    
    # Analyze rule-based impact
    overrides = 0
    for i in range(len(X_test)):
        # Calculate sum of specific HIGH RISK APIs (exclude Add-Type which is common in benign)
        # We focus on Memory Injection & Bypass APIs
        high_risk_apis_sum = sum([
            X_test[i, win32_idx_start + win32_apis.index('VirtualAlloc')],
            X_test[i, win32_idx_start + win32_apis.index('CreateThread')],
            X_test[i, win32_idx_start + win32_apis.index('WriteProcessMemory')],
            X_test[i, win32_idx_start + win32_apis.index('AmsiScanBuffer')],
            X_test[i, win32_idx_start + win32_apis.index('EtwEventWrite')],
            X_test[i, win32_idx_start + win32_apis.index('DllImport')],
        ])
        
        # Hybrid Logic: If high-risk API called -> Malicious. Else -> use ML.
        if high_risk_apis_sum >= 1:
            y_pred_final.append(1)
            if y_pred_ml[i] == 0:
                overrides += 1
        else:
            y_pred_final.append(y_pred_ml[i])
            
    y_pred_final = np.array(y_pred_final)
    
    acc = accuracy_score(y_test, y_pred_final)
    prec = precision_score(y_test, y_pred_final)
    rec = recall_score(y_test, y_pred_final)
    f1 = f1_score(y_test, y_pred_final)
    
    print("\n=================================================================")
    print("  RESULTS OF HYBRID MODEL (RULE-BASED + ML)")
    print("=================================================================")
    print(f"  Overrides (Rule caught what ML missed): {overrides}")
    print(f"  Accuracy:  {acc:.4f}")
    print(f"  Precision: {prec:.4f}")
    print(f"  Recall:    {rec:.4f}")
    print(f"  F1-Score:  {f1:.4f}")
    
    res_dir = os.path.join(PROJECT_ROOT, "results", "enhanced")
    os.makedirs(res_dir, exist_ok=True)
    
    # Confusion Matrix
    setup_plot_style()
    cm = confusion_matrix(y_test, y_pred_final)
    fig, ax = plt.subplots(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Greens',
                xticklabels=['Benign', 'Malicious'],
                yticklabels=['Benign', 'Malicious'],
                annot_kws={'size': 14, 'weight': 'bold'})
    ax.set_title('Confusion Matrix - Hybrid Model', fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.savefig(os.path.join(res_dir, "hybrid_confusion_matrix.png"), dpi=200)
    plt.close()

if __name__ == "__main__":
    main()
