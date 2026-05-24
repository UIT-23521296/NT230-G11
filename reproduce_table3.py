"""
Reproduce Table 3 from the paper:
"Comparison of the effects of models with different structures on mixed scripts."

Compares:
1. M-FastText-3 (Hybrid with 3-grams)
2. M-FastText-2 (Hybrid with 2-grams)
3. M-FastText-1 (Hybrid with 1-grams)
4. Manual (Textual + Token + AST only)
5. FastText-3 (FastText 3-grams only)
6. FastText-2 (FastText 2-grams only)
7. FastText-1 (FastText 1-grams only)
"""

import numpy as np
from tqdm import tqdm
import m_fasttext2_model as core

def main():
    print("=" * 65)
    print(" REPRODUCE TABLE 3: MIXED SCRIPTS EXPERIMENT")
    print("=" * 65)

    # 1. Load Data
    print("\n[1] Loading dataset...")
    mal_scripts, _ = core.load_scripts(core.MIXED_DIR, "Loading mixed_malicious")
    ben_scripts, _ = core.load_scripts(core.BENIGN_DIR, "Loading benign")
    
    mal_scripts = [s for s in mal_scripts if len(s.strip()) > 0]
    ben_scripts = [s for s in ben_scripts if len(s.strip()) > 0]
    all_scripts = mal_scripts + ben_scripts
    y = np.array([1]*len(mal_scripts) + [0]*len(ben_scripts))

    # 2. Discover Tokens
    top_funcs, top_members = core.discover_top_tokens(
        mal_scripts, all_scripts, core.TOP_K_FUNCTIONS, core.TOP_K_MEMBERS
    )

    # 3. Extract Manual Features
    print("\n[2] Extracting Manual Features (274 dims)...")
    manual_features = []
    for s in tqdm(all_scripts, desc="  Extracting", ncols=80):
        textual = core.extract_textual_features(s)
        token = core.extract_token_features(s, top_funcs, top_members)
        ast = core.extract_ast_features(s)
        manual_features.append(textual + token + ast)
    manual_features = np.array(manual_features, dtype=np.float64)

    # Helper function for FastText
    def get_ft_features(n_gram):
        print(f"\n[3] Training FastText-{n_gram}...")
        core.FASTTEXT_MIN_N = n_gram
        core.FASTTEXT_MAX_N = n_gram
        model = core.train_fasttext_model(all_scripts)
        
        print(f"  Extracting FastText-{n_gram} embeddings (300 dims)...")
        features = [core.get_script_embedding(s, model) for s in tqdm(all_scripts, ncols=80)]
        return np.array(features, dtype=np.float64)

    # 4. Train FastText models
    ft1_features = get_ft_features(1)
    ft2_features = get_ft_features(2)
    ft3_features = get_ft_features(3)

    # 5. Build Configurations
    configs = {
        "M-FastText-3": np.hstack([ft3_features, manual_features]),
        "M-FastText-2": np.hstack([ft2_features, manual_features]),
        "M-FastText-1": np.hstack([ft1_features, manual_features]),
        "Manual":       manual_features,
        "FastText-3":   ft3_features,
        "FastText-2":   ft2_features,
        "FastText-1":   ft1_features,
    }

    # 6. Run Evaluation
    print("\n[4] Running 5-Fold Cross Validation for all models...")
    results_summary = []
    
    # Temporarily mute print output from core to keep it clean
    import sys, os
    old_stdout = sys.stdout
    
    for name, X in configs.items():
        print(f"  Evaluating {name:<15} (Features: {X.shape[1]})...")
        sys.stdout = open(os.devnull, 'w', encoding='utf-8')
        try:
            res = core.run_experiment(X, y, experiment_name=name)
        finally:
            sys.stdout.close()
            sys.stdout = old_stdout
            
        results_summary.append({
            'Model': name,
            'Accuracy': res['avg_accuracy'],
            'Precision': res['avg_precision'],
            'Recall': res['avg_recall'],
            'F1-Score': res['avg_f1'],
        })

    # 7. Print Table 3
    print("\n\n" + "═" * 70)
    print("  TABLE 3: Comparison of models on mixed scripts (5-Fold CV)")
    print("═" * 70)
    print(f"  {'Model':<15} │ {'Precision':<10} │ {'Recall':<10} │ {'F1-score':<10} │ {'Accuracy':<10}")
    print("  " + "─" * 68)
    for r in results_summary:
        print(f"  {r['Model']:<15} │ {r['Precision']:<10.4f} │ {r['Recall']:<10.4f} │ {r['F1-Score']:<10.4f} │ {r['Accuracy']:<10.4f}")
    print("═" * 70)
    print("\n  Note: Loss metrics from the paper are equivalent to 1 - Accuracy.")

if __name__ == "__main__":
    main()
