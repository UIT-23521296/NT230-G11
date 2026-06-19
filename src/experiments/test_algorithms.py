import os
import sys
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import recall_score

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.core import m_fasttext2_model_enhanced as core

def main():
    mpsd_mal_dir = os.path.join(PROJECT_ROOT, "data", "mpsd", "malicious_pure")
    mpsd_ben_dir = os.path.join(PROJECT_ROOT, "data", "mpsd", "powershell_benign_dataset")
    new_mal_dir = os.path.join(PROJECT_ROOT, "data", "new_dataset", "malicious")
    new_ben_dir = os.path.join(PROJECT_ROOT, "data", "new_dataset", "benign")
    
    mpsd_mal, _ = core.load_scripts(mpsd_mal_dir, desc="MPSD mal")
    mpsd_ben, _ = core.load_scripts(mpsd_ben_dir, desc="MPSD ben")
    new_mal, _ = core.load_scripts(new_mal_dir, desc="New mal")
    new_ben, _ = core.load_scripts(new_ben_dir, desc="New ben")
    
    # Subsample to speed up this quick test
    train_scripts = mpsd_mal[:1000] + mpsd_ben[:1000]
    y_train = np.array([1]*1000 + [0]*1000)
    
    test_scripts = new_mal + new_ben
    y_test = np.array([1]*len(new_mal) + [0]*len(new_ben))
    
    top_funcs, top_members = core.discover_top_tokens(mpsd_mal[:1000], mpsd_ben[:1000], train_scripts)
    ft_model = core.train_fasttext_model(train_scripts)
    
    X_train_raw = core.extract_all_features(train_scripts, ft_model, top_funcs, top_members)
    X_test_raw = core.extract_all_features(test_scripts, ft_model, top_funcs, top_members)
    
    X_train_raw = np.nan_to_num(X_train_raw, nan=0.0)
    X_test_raw = np.nan_to_num(X_test_raw, nan=0.0)
    
    ft_dim = core.FASTTEXT_DIM
    ft_clf = LogisticRegression(random_state=0, max_iter=100)
    ft_clf.fit(X_train_raw[:, :ft_dim], y_train)
    
    X_train = np.hstack([ft_clf.predict(X_train_raw[:, :ft_dim]).reshape(-1,1), 
                         ft_clf.predict_proba(X_train_raw[:, :ft_dim])[:,1].reshape(-1,1), 
                         X_train_raw[:, ft_dim:]])
    X_test = np.hstack([ft_clf.predict(X_test_raw[:, :ft_dim]).reshape(-1,1), 
                        ft_clf.predict_proba(X_test_raw[:, :ft_dim])[:,1].reshape(-1,1), 
                        X_test_raw[:, ft_dim:]])
    
    # Evaluate RF
    rf = RandomForestClassifier(n_estimators=70, max_features=8, random_state=0, n_jobs=-1)
    rf.fit(X_train, y_train)
    print(f"Random Forest Recall: {recall_score(y_test, rf.predict(X_test)):.4f}")
    
    # Evaluate MLP
    mlp = MLPClassifier(hidden_layer_sizes=(100, 50), max_iter=300, random_state=0)
    mlp.fit(X_train, y_train)
    print(f"MLP (Neural Net) Recall: {recall_score(y_test, mlp.predict(X_test)):.4f}")
    
    # Evaluate GBDT
    gbdt = GradientBoostingClassifier(n_estimators=100, random_state=0)
    gbdt.fit(X_train, y_train)
    print(f"GBDT Recall: {recall_score(y_test, gbdt.predict(X_test)):.4f}")

if __name__ == "__main__":
    main()
