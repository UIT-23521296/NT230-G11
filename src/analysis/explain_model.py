import os
import sys
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression

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
    print("  EXPLAINABLE AI - FEATURE IMPORTANCE ANALYSIS")
    print("=================================================================")
    
    # 1. Load Data
    mpsd_mal_dir = os.path.join(PROJECT_ROOT, "data", "mpsd", "malicious_pure")
    mpsd_ben_dir = os.path.join(PROJECT_ROOT, "data", "mpsd", "powershell_benign_dataset")
    
    mpsd_mal, _ = core.load_scripts(mpsd_mal_dir, desc="MPSD malicious")
    mpsd_ben, _ = core.load_scripts(mpsd_ben_dir, desc="MPSD benign")
    
    # Use 1000 samples for fast training
    train_scripts = mpsd_mal[:1000] + mpsd_ben[:1000]
    y_train = np.array([1]*1000 + [0]*1000)
    
    # 2. Extract features
    top_funcs, top_members = core.discover_top_tokens(mpsd_mal[:1000], mpsd_ben[:1000], train_scripts)
    ft_model = core.train_fasttext_model(train_scripts)
    X_train_raw = core.extract_all_features(train_scripts, ft_model, top_funcs, top_members, desc="Extracting features")
    X_train_raw = np.nan_to_num(X_train_raw, nan=0.0, posinf=0.0, neginf=0.0)
    
    ft_dim = core.FASTTEXT_DIM
    ft_clf = LogisticRegression(random_state=core.RF_RANDOM_STATE, max_iter=100)
    ft_clf.fit(X_train_raw[:, :ft_dim], y_train)
    
    yt_pred = ft_clf.predict(X_train_raw[:, :ft_dim]).reshape(-1, 1)
    yt_proba = ft_clf.predict_proba(X_train_raw[:, :ft_dim])[:, 1].reshape(-1, 1)
    X_train = np.hstack([yt_pred, yt_proba, X_train_raw[:, ft_dim:]])
    
    # Tên của 93 đặc trưng
    feature_names = ["FT_Pred", "FT_Proba"]
    feature_names += [
        "Shellcode", "Entropy", "Ascii_Top1", "Ascii_Top2", "Ascii_Top3", "Ascii_Top4", "Ascii_Top5",
        "Num_Strings", "Max_Str_Len", "Avg_Str_Len", "URL_IP", "Total_Vars", "Special_Vars"
    ]
    feature_names += ["Function_Rating"] + [f"Member_{i}" for i in range(1, 34)]
    feature_names += list(core.AST_23_NODE_PATTERNS.keys())
    feature_names += list(core.AST_5_SPECIAL_PATTERNS.keys())
    feature_names += ["AST_Depth"]
    
    win32_apis = [
        'VirtualAlloc', 'CreateThread', 'WriteProcessMemory', 'LoadLibrary',
        'GetProcAddress', 'AmsiScanBuffer', 'EtwEventWrite', 'Add-Type',
        'DllImport', 'System.Reflection', 'System.InteropServices',
        'Net.Sockets', 'Cryptography'
    ]
    feature_names += win32_apis
    
    # 3. Train RF
    print("\nTraining Random Forest...")
    rf = RandomForestClassifier(n_estimators=70, max_features=8, random_state=0, n_jobs=-1)
    rf.fit(X_train, y_train)
    
    # 4. Extract Feature Importances
    importances = rf.feature_importances_
    indices = np.argsort(importances)[-20:] # Top 20 features
    
    top_features = [feature_names[i] for i in indices]
    top_importances = importances[indices]
    
    res_dir = os.path.join(PROJECT_ROOT, "results", "enhanced")
    os.makedirs(res_dir, exist_ok=True)
    
    setup_plot_style()
    plt.figure(figsize=(10, 8))
    bars = plt.barh(range(len(top_importances)), top_importances, color='#d32f2f')
    plt.yticks(range(len(top_importances)), top_features)
    plt.xlabel('Tầm Quan Trọng (Gini Importance)')
    plt.title('Top 20 Đặc Trưng Quyết Định Của Mô Hình (MPSD-Trained)')
    
    # Add values on bars
    for bar in bars:
        width = bar.get_width()
        plt.text(width + 0.002, bar.get_y() + bar.get_height()/2.0,
                 f'{width:.3f}', ha='left', va='center', fontsize=10)
                 
    plt.tight_layout()
    plt.savefig(os.path.join(res_dir, "feature_importance_plot.png"), dpi=200)
    plt.close()
    
    print(f"\n=> Đã lưu biểu đồ Giải thích AI tại: {os.path.join(res_dir, 'feature_importance_plot.png')}")
    print("Hoàn thành!")

if __name__ == "__main__":
    main()
