"""
================================================================================
M-FastText-2 Model Re-Implementation
================================================================================
Paper: "Effective method for detecting malicious PowerShell scripts
        based on hybrid features"
Authors: Yong Fang, Xiangyu Zhou, Cheng Huang
Published: Neurocomputing, 2021, Vol. 448, pp. 30-39
DOI: 10.1016/j.neucom.2021.03.117

Model: M-FastText-2
  - FastText skip-gram with character 2-grams (300-dim)
  - Hybrid Features: Textual + Token + AST Node
  - Classifier: Random Forest

Evaluation: 5-fold Stratified Cross-Validation
================================================================================
"""

import os
import re
import sys
import math
import time
import json
import pickle
import warnings
import numpy as np
from collections import Counter, OrderedDict

# Suppress warnings
warnings.filterwarnings('ignore')

# Optional imports with graceful fallback
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
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns


# ============================================================
# CONFIGURATION - Exact parameters from the paper
# ============================================================

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_DIR = os.path.join(BASE_DIR, "mpsd")
MALICIOUS_DIR = os.path.join(DATASET_DIR, "malicious_pure")
MIXED_DIR = os.path.join(DATASET_DIR, "mixed_malicious")
BENIGN_DIR = os.path.join(DATASET_DIR, "powershell_benign_dataset")
RESULTS_DIR = os.path.join(BASE_DIR, "results", "78dim")

# FastText Parameters (Section 3.3.3 & 4.3)
FASTTEXT_DIM = 300          # Word vector dimension: 300
FASTTEXT_SG = 1             # Skip-gram mode
FASTTEXT_MIN_N = 2          # Character n-gram min = 2
FASTTEXT_MAX_N = 2          # Character n-gram max = 2 → "M-FastText-2"
FASTTEXT_WINDOW = 5         # Context window size
FASTTEXT_MIN_COUNT = 1      # Include all words
FASTTEXT_EPOCHS = 10        # Training epochs

# Random Forest Parameters (Section 3.4)
RF_N_ESTIMATORS = 70        # Number of trees
RF_MAX_FEATURES = 8         # Max features per split
RF_RANDOM_STATE = 0         # Random seed

# Cross-Validation
N_FOLDS = 5                 # 5-fold stratified CV

# Token Feature Parameters (Section 3.2.2)
TOP_K_FUNCTIONS = 200       # Top 200 functions scoring
TOP_K_MEMBERS = 33          # Top 33 member tokens distribution


# ============================================================
# 1. DATA LOADING
# ============================================================

def load_scripts(directory, desc="Loading"):
    """
    Load all .ps1 PowerShell scripts from a directory.
    Handles encoding issues and antivirus blocks gracefully.
    """
    scripts = []
    filenames = []
    errors = 0

    ps1_files = sorted([f for f in os.listdir(directory) if f.endswith('.ps1')])

    for f in tqdm(ps1_files, desc=desc, ncols=80):
        filepath = os.path.join(directory, f)
        content = ""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as fh:
                content = fh.read()
        except Exception:
            try:
                with open(filepath, 'r', encoding='latin-1', errors='ignore') as fh:
                    content = fh.read()
            except Exception:
                errors += 1

        scripts.append(content)
        filenames.append(f)

    if errors > 0:
        print(f"  [WARNING] {errors}/{len(ps1_files)} files could not be read "
              f"(possible antivirus block)")

    return scripts, filenames


# ============================================================
# 2. TEXTUAL FEATURES (Section 3.2.1)
#    12 features total
# ============================================================

def detect_shellcode(script):
    """
    Detect existence of shellcode patterns in the script (binary: 0/1).
    Looks for hex byte arrays, C-style hex escapes, byte array casts,
    and long Base64-encoded strings.
    """
    patterns = [
        r'0x[0-9a-fA-F]{2}[,\s;\)]',       # Hex byte arrays: 0x4D, 0x5A
        r'\\x[0-9a-fA-F]{2}',                # C-style hex escapes: \x4D
        r'\[Byte\s*\[\s*\]\s*\]',             # PowerShell byte array cast
        r'(?:[A-Za-z0-9+/]{4}){12,}={0,2}',  # Long Base64 strings
    ]
    for p in patterns:
        if re.search(p, script):
            return 1
    return 0


def calculate_entropy(script):
    """
    Calculate Shannon information entropy of the script text.
    Higher entropy indicates more randomness (often seen in obfuscated code).
    """
    if not script or len(script) == 0:
        return 0.0
    counter = Counter(script)
    length = len(script)
    entropy = 0.0
    for count in counter.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def get_top5_chars_ascii(script):
    """
    Get ASCII codes of the top 5 most frequent characters in the script.
    Returns a list of 5 integers.
    """
    if not script:
        return [0, 0, 0, 0, 0]
    counter = Counter(script)
    top5 = counter.most_common(5)
    result = [ord(char) for char, _ in top5]
    while len(result) < 5:
        result.append(0)
    return result[:5]


def get_string_features(script):
    """
    Extract string-related features:
      - Number of string literals
      - Maximum string length
      - Average string length
    """
    strings_double = re.findall(r'"([^"]*)"', script)
    strings_single = re.findall(r"'([^']*)'", script)
    all_strings = strings_double + strings_single

    num_strings = len(all_strings)
    if all_strings:
        lengths = [len(s) for s in all_strings]
        max_len = max(lengths)
        avg_len = sum(lengths) / len(lengths)
    else:
        max_len = 0
        avg_len = 0.0

    return num_strings, max_len, avg_len


def detect_url_ip(script):
    """
    Detect presence of URLs or IP addresses in the script (binary: 0/1).
    Critical for detecting scripts that download payloads.
    """
    url_pattern = r'https?://[^\s\'"<>)}\]]+'
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    has_url = 1 if re.search(url_pattern, script, re.IGNORECASE) else 0
    has_ip = 1 if re.search(ip_pattern, script) else 0
    return max(has_url, has_ip)


def count_special_variables(script):
    """
    Count special variable names commonly associated with malware.
    Variables like $cmd, $Shell, $c, etc.
    """
    special_names = [
        'cmd', 'shell', 'c', 'exec', 'download', 'payload',
        'shellcode', 'inject', 'exploit', 'bypass',
        'encode', 'decode', 'base64', 'compress',
        'webclient', 'socket', 'stream', 'http',
        'wscript', 'powershell', 'hidden'
    ]
    script_lower = script.lower()
    count = 0
    for name in special_names:
        # Match $variableName pattern
        count += len(re.findall(r'\$' + re.escape(name) + r'\b', script_lower))
    return count


def extract_textual_features(script):
    """
    Extract all textual features as described in Section 3.2.1.

    Returns: 12-dimensional feature vector
      [0]     Shellcode existence (0/1)
      [1]     Information entropy
      [2-6]   Top 5 most frequent characters (ASCII codes)
      [7]     Number of string literals
      [8]     Maximum string length
      [9]     Average string length
      [10]    URL/IP existence (0/1)
      [11]    Special variable count
    """
    features = []

    # 1. Shellcode existence (1 feature)
    features.append(detect_shellcode(script))

    # 2. Information Entropy (1 feature)
    features.append(calculate_entropy(script))

    # 3. Top 5 most frequent characters as ASCII (5 features)
    features.extend(get_top5_chars_ascii(script))

    # 4. String features: count, max_length, avg_length (3 features)
    num_str, max_len, avg_len = get_string_features(script)
    features.extend([num_str, max_len, avg_len])

    # 5. URL/IP existence (1 feature)
    features.append(detect_url_ip(script))

    # 6. Special variable names count (2 features: total vars, special vars)
    total_vars = len(re.findall(r'\$[A-Za-z_]\w*', script))
    features.append(total_vars)
    features.append(count_special_variables(script))

    return features  # Total: 13 features


# ============================================================
# 3. TOKEN FEATURES (Section 3.2.2)
#    200 function scores + 33 member token ratios = 233 features
# ============================================================

def extract_function_calls(script):
    """
    Extract all function/cmdlet invocations from a PowerShell script.
    Matches Verb-Noun cmdlet patterns and standalone function calls.
    """
    # PowerShell cmdlet pattern: Verb-Noun (e.g., Get-Process, Invoke-Expression)
    cmdlet_pattern = r'\b([A-Za-z]+-[A-Za-z]\w*)\b'
    # Standalone function calls before parenthesis
    func_pattern = r'\b([A-Za-z_]\w*)\s*\('

    cmdlets = re.findall(cmdlet_pattern, script)
    functions = re.findall(func_pattern, script)

    # Combine and normalize to lowercase
    all_funcs = [f.lower() for f in cmdlets + functions]
    return all_funcs


def extract_member_accesses(script):
    """
    Extract all member access tokens from a PowerShell script.
    Matches .MemberName and ::StaticMember patterns.
    These represent method calls and property accesses on objects.
    """
    # .MemberName pattern (e.g., $obj.DownloadString)
    dot_members = re.findall(r'\.([A-Za-z_]\w*)', script)
    # ::StaticMember pattern (e.g., [Convert]::FromBase64String)
    static_members = re.findall(r'::([A-Za-z_]\w*)', script)

    all_members = dot_members + static_members
    return all_members


def discover_top_tokens(malicious_scripts, benign_scripts, all_scripts,
                        k_functions=200, k_members=33):
    """
    First pass: discover the top-K most frequent tokens from the corpus.

    - Top 200 functions: extracted from ALL scripts, ranked by frequency. 
      Then scored +1 (more in mal) or -1 (more in ben).
    - Top 33 member tokens: extracted from MALICIOUS scripts only,
      representing the most characteristic member access patterns in malware

    Returns: (top_functions_scores, top_members_list)
    """
    print("\n[Phase 2] Discovering top tokens from corpus...")

    # Discover top functions from ALL scripts
    func_counter = Counter()
    for script in tqdm(all_scripts, desc="  Scanning functions (all)", ncols=80):
        funcs = extract_function_calls(script)
        func_counter.update(funcs)

    top_functions = [func for func, _ in func_counter.most_common(k_functions)]
    
    # Calculate +1/-1 scores for top 200 functions
    mal_func_counter = Counter()
    for script in malicious_scripts:
        mal_func_counter.update(extract_function_calls(script))
        
    ben_func_counter = Counter()
    for script in benign_scripts:
        ben_func_counter.update(extract_function_calls(script))
        
    top_functions_scores = {}
    for func in top_functions:
        mal_count = mal_func_counter.get(func, 0)
        ben_count = ben_func_counter.get(func, 0)
        
        if mal_count > ben_count:
            top_functions_scores[func] = 1
        else:
            top_functions_scores[func] = -1

    # Discover top member tokens from MALICIOUS scripts only
    member_counter = Counter()
    for script in tqdm(malicious_scripts,
                       desc="  Scanning members (malicious)", ncols=80):
        members = extract_member_accesses(script)
        member_counter.update(members)

    top_members = [member for member, _ in member_counter.most_common(k_members)]

    print(f"  Discovered {len(top_functions)} top functions (scored), "
          f"{len(top_members)} top member tokens")
    if top_members:
        print(f"  Top 10 member tokens: {top_members[:10]}")

    return top_functions_scores, top_members


def extract_token_features(script, top_functions_scores, top_members):
    """
    Extract token features as described in Section 3.2.2.

    - Top 200 functions scoring: total rating (1 feature)
    - Top 33 member tokens: distribution ratio of each member token
      relative to total member accesses (33 features)

    Returns: 34-dimensional feature vector
    """
    features = []

    # --- Top 200 Functions Scoring (Total Rating) ---
    script_funcs = extract_function_calls(script)
    total_rating = 0
    for func in script_funcs:
        if func in top_functions_scores:
            total_rating += top_functions_scores[func]
    features.append(total_rating)

    # --- Top 33 Member Tokens Distribution Ratio ---
    script_members = extract_member_accesses(script)
    member_counts = Counter(script_members)
    total_members = sum(member_counts.values())

    for member in top_members:
        if total_members > 0:
            features.append(member_counts.get(member, 0) / total_members)
        else:
            features.append(0.0)

    return features  # Total: 1 + 33 = 34 features


# ============================================================
# 4. AST NODE FEATURES (Section 3.2.3)
#    23 main nodes + 5 special nodes + 1 AST depth = 29 features
# ============================================================

# 23 main AST nodes (from Figure 4 of the paper)
# These are the most common nodes in PowerShell AST, detected via regex
AST_23_NODE_PATTERNS = OrderedDict([
    # --- Statement-level nodes ---
    ('ScriptBlockAst',              r'\{'),
    ('NamedBlockAst',               r'\b(?:begin|process|end|dynamicparam)\s*\{'),
    ('StatementBlockAst',           r'(?:if|else|for|foreach|while|switch|try|catch|finally)\s*\{'),
    ('PipelineAst',                 r'\|'),
    ('AssignmentStatementAst',      r'(?<!\w)\$\w+\s*[-+*/%]?=(?!=)'),
    ('IfStatementAst',              r'\bif\s*\('),
    ('ForEachStatementAst',         r'\b(?:foreach)\s*\('),
    ('WhileStatementAst',           r'\bwhile\s*\('),
    ('ForStatementAst',             r'\bfor\s*\('),
    ('DoWhileStatementAst',         r'\bdo\s*\{'),
    ('SwitchStatementAst',          r'\bswitch\b'),
    ('TryStatementAst',             r'\btry\s*\{'),
    ('ReturnStatementAst',          r'\breturn\b'),
    ('ThrowStatementAst',           r'\bthrow\b'),
    ('ExitStatementAst',            r'\bexit\b'),
    ('BreakStatementAst',           r'\bbreak\b'),
    ('ContinueStatementAst',        r'\bcontinue\b'),
    ('FunctionDefinitionAst',       r'\bfunction\s+[\w-]+'),

    # --- Expression-level nodes ---
    ('CommandAst',                  r'\b[A-Z][a-z]+-[A-Z]\w*'),
    ('CommandParameterAst',         r'(?<=\s)-[A-Za-z]\w*'),
    ('VariableExpressionAst',       r'\$[A-Za-z_]\w*'),
    ('MemberExpressionAst',         r'(?:\.\w+|\:\:\w+)(?!\s*\()'),
    ('InvokeMemberExpressionAst',   r'(?:\.\w+|\:\:\w+)\s*\('),
])

# 5 special AST nodes (primarily found in malware)
AST_5_SPECIAL_PATTERNS = OrderedDict([
    ('TypeExpressionAst',           r'\[\s*[A-Za-z][\w.]*\s*\]'),
    ('ConvertExpressionAst',        r'\[\s*[A-Za-z][\w.]*\s*\]\s*\$'),
    ('ScriptBlockExpressionAst',    r'(?:\$\w+\s*=\s*\{|\{\s*param\s*\()'),
    ('SubExpressionAst',            r'\$\('),
    ('IndexExpressionAst',          r'\$\w+\s*\['),
])


def calculate_ast_depth(script):
    """
    Calculate the maximum nesting depth of the AST.
    Approximated by tracking brace {} nesting depth,
    ignoring braces inside string literals.
    """
    max_depth = 0
    current_depth = 0
    in_single_quote = False
    in_double_quote = False
    prev_char = ''

    for char in script:
        if char == "'" and not in_double_quote and prev_char != '`':
            in_single_quote = not in_single_quote
        elif char == '"' and not in_single_quote and prev_char != '`':
            in_double_quote = not in_double_quote
        elif not in_single_quote and not in_double_quote:
            if char == '{':
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            elif char == '}':
                current_depth = max(0, current_depth - 1)
        prev_char = char

    return max_depth


def extract_ast_features(script):
    """
    Extract AST node features as described in Section 3.2.3.

    - 23 main AST nodes (Figure 4): frequency count of each
    - 5 special nodes (malware-specific): frequency count
    - AST depth: maximum nesting depth

    Returns: 29-dimensional feature vector
    """
    features = []

    # 23 main AST nodes
    for node_name, pattern in AST_23_NODE_PATTERNS.items():
        try:
            count = len(re.findall(pattern, script, re.IGNORECASE | re.MULTILINE))
        except re.error:
            count = 0
        features.append(count)

    # 5 special AST nodes
    for node_name, pattern in AST_5_SPECIAL_PATTERNS.items():
        try:
            count = len(re.findall(pattern, script, re.IGNORECASE | re.MULTILINE))
        except re.error:
            count = 0
        features.append(count)

    # AST depth (1 feature)
    features.append(calculate_ast_depth(script))

    return features  # Total: 23 + 5 + 1 = 29 features


# ============================================================
# 5. FASTTEXT EMBEDDING (Section 3.3.3 & 4.3)
#    300-dimensional, skip-gram, character 2-grams
# ============================================================

def tokenize_script(script):
    """
    Tokenize a PowerShell script into words for FastText training.
    Removes comments and splits on whitespace/punctuation boundaries.
    """
    # Remove single-line comments
    text = re.sub(r'#.*$', '', script, flags=re.MULTILINE)
    # Remove multi-line comments
    text = re.sub(r'<#[\s\S]*?#>', '', text)

    # Tokenize: extract words, variables, operators
    tokens = re.findall(r'[A-Za-z_$][\w\-]*|[^\s\w]', text)
    tokens = [t.lower() for t in tokens if len(t) > 0]

    return tokens


def train_fasttext_model(all_scripts):
    """
    Train FastText model as described in Section 3.3.3 & 4.3.

    Parameters (from the paper):
      - vector_size = 300  (300-dimensional word vectors)
      - sg = 1             (skip-gram mode)
      - min_n = 2          (character n-gram minimum = 2)
      - max_n = 2          (character n-gram maximum = 2)
                           This is why it's called "M-FastText-2"
      - window = 5         (context window)
      - min_count = 1      (include all words)
      - epochs = 10        (training iterations)
    """
    print("\n[Phase 3] Training FastText model...")
    print(f"  Parameters: dim={FASTTEXT_DIM}, sg=skip-gram, "
          f"n-grams={FASTTEXT_MIN_N}-{FASTTEXT_MAX_N}, "
          f"window={FASTTEXT_WINDOW}, epochs={FASTTEXT_EPOCHS}")

    # Tokenize all scripts into sentences
    sentences = []
    for script in tqdm(all_scripts, desc="  Tokenizing scripts", ncols=80):
        tokens = tokenize_script(script)
        if tokens:
            sentences.append(tokens)

    print(f"  Total sentences (scripts): {len(sentences)}")
    print(f"  Training FastText model (this may take a few minutes)...")

    model = GensimFastText(
        sentences=sentences,
        vector_size=FASTTEXT_DIM,
        sg=FASTTEXT_SG,
        min_n=FASTTEXT_MIN_N,
        max_n=FASTTEXT_MAX_N,
        window=FASTTEXT_WINDOW,
        min_count=FASTTEXT_MIN_COUNT,
        epochs=FASTTEXT_EPOCHS,
        workers=4,
        seed=RF_RANDOM_STATE,
    )

    print(f"  FastText vocabulary size: {len(model.wv)}")
    return model


def get_script_embedding(script, fasttext_model):
    """
    Get 300-dimensional embedding for a script.
    The script is tokenized into words, and the embedding is computed
    as the average of all word vectors (as described in the paper).
    """
    tokens = tokenize_script(script)
    if not tokens:
        return np.zeros(FASTTEXT_DIM)

    vectors = []
    for token in tokens:
        try:
            vec = fasttext_model.wv[token]
            vectors.append(vec)
        except KeyError:
            continue

    if vectors:
        return np.mean(vectors, axis=0)
    else:
        return np.zeros(FASTTEXT_DIM)


# ============================================================
# 6. FEATURE EXTRACTION PIPELINE
# ============================================================

def extract_all_features(scripts, fasttext_model, top_functions, top_members,
                         desc="Extracting features"):
    """
    Extract all hybrid features for a list of scripts.

    For each script, concatenates:
      - FastText embedding (300 dim - will be reduced to 2 dim in CV)
      - Textual features (13 dim)
      - Token features (34 dim)
      - AST features (29 dim)

    Total returned: 376-dimensional feature vector per script (FastText simulated to 2D later)
    """
    all_features = []

    for script in tqdm(scripts, desc=desc, ncols=80):
        # FastText embedding (300 dim)
        embedding = get_script_embedding(script, fasttext_model)

        # Textual features (13 dim) - Section 3.2.1
        textual = extract_textual_features(script)

        # Token features (34 dim) - Section 3.2.2
        token = extract_token_features(script, top_functions, top_members)

        # AST features (29 dim) - Section 3.2.3
        ast = extract_ast_features(script)

        # Concatenate all features
        feature_vector = np.concatenate([
            embedding,
            np.array(textual, dtype=np.float64),
            np.array(token, dtype=np.float64),
            np.array(ast, dtype=np.float64),
        ])

        all_features.append(feature_vector)

    return np.array(all_features)


# ============================================================
# 7. MODEL TRAINING & EVALUATION
# ============================================================

def run_experiment(X, y, experiment_name="Experiment"):
    """
    Run 5-fold stratified cross-validation with Random Forest.

    Random Forest Parameters (Section 3.4):
      - n_estimators = 70
      - max_features = 8
      - random_state = 0
    """
    print(f"\n{'=' * 65}")
    print(f"  {experiment_name}")
    print(f"{'=' * 65}")
    print(f"  Dataset size:      {len(X)} samples")
    print(f"  Feature dimension: {X.shape[1]}")

    label_counts = Counter(y)
    print(f"  Class distribution: Benign={label_counts[0]}, "
          f"Malicious={label_counts[1]}")

    # Replace NaN/Inf with 0
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

    skf = StratifiedKFold(
        n_splits=N_FOLDS,
        shuffle=True,
        random_state=RF_RANDOM_STATE
    )

    fold_results = []
    all_y_true = []
    all_y_pred = []
    all_y_proba = []

    print(f"\n  {'Fold':<6} {'Accuracy':<11} {'Precision':<11} "
          f"{'Recall':<11} {'F1-Score':<11}")
    print(f"  {'─' * 50}")

    for fold, (train_idx, test_idx) in enumerate(skf.split(X, y), 1):
        X_train, X_test = X[train_idx], X[test_idx]
        y_train, y_test = y[train_idx], y[test_idx]
        
        # --- Simulate FastText Supervised Output (300D -> 2D) ---
        X_train_ft = X_train[:, :FASTTEXT_DIM]
        X_train_manual = X_train[:, FASTTEXT_DIM:]
        
        X_test_ft = X_test[:, :FASTTEXT_DIM]
        X_test_manual = X_test[:, FASTTEXT_DIM:]
        
        # Train FastText simulated classifier (Logistic Regression) on embeddings
        ft_clf = LogisticRegression(random_state=RF_RANDOM_STATE, max_iter=1000)
        ft_clf.fit(X_train_ft, y_train)
        
        # Get 2D features: Predict label, predict proba
        y_train_ft_pred = ft_clf.predict(X_train_ft).reshape(-1, 1)
        y_train_ft_proba = ft_clf.predict_proba(X_train_ft)[:, 1].reshape(-1, 1)
        
        y_test_ft_pred = ft_clf.predict(X_test_ft).reshape(-1, 1)
        y_test_ft_proba = ft_clf.predict_proba(X_test_ft)[:, 1].reshape(-1, 1)
        
        # Combine 2D FastText features with 76D manual features = 78D
        X_train_final = np.hstack([y_train_ft_pred, y_train_ft_proba, X_train_manual])
        X_test_final = np.hstack([y_test_ft_pred, y_test_ft_proba, X_test_manual])

        # Train Random Forest with exact paper parameters on 78D features
        clf = RandomForestClassifier(
            n_estimators=RF_N_ESTIMATORS,
            max_features=RF_MAX_FEATURES,
            random_state=RF_RANDOM_STATE,
            n_jobs=-1,
        )
        clf.fit(X_train_final, y_train)

        # Predict
        y_pred = clf.predict(X_test_final)
        y_proba = clf.predict_proba(X_test_final)[:, 1]

        # Metrics
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred)
        rec = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)

        fold_results.append({
            'fold': fold, 'accuracy': acc,
            'precision': prec, 'recall': rec, 'f1': f1
        })

        all_y_true.extend(y_test)
        all_y_pred.extend(y_pred)
        all_y_proba.extend(y_proba)

        print(f"  {fold:<6} {acc:<11.4f} {prec:<11.4f} "
              f"{rec:<11.4f} {f1:<11.4f}")

    # Average metrics
    avg_acc = np.mean([r['accuracy'] for r in fold_results])
    avg_prec = np.mean([r['precision'] for r in fold_results])
    avg_rec = np.mean([r['recall'] for r in fold_results])
    avg_f1 = np.mean([r['f1'] for r in fold_results])

    std_acc = np.std([r['accuracy'] for r in fold_results])

    print(f"  {'─' * 50}")
    print(f"  {'AVG':<6} {avg_acc:<11.4f} {avg_prec:<11.4f} "
          f"{avg_rec:<11.4f} {avg_f1:<11.4f}")
    print(f"  Accuracy std: ±{std_acc:.4f}")

    # Full Classification Report
    print(f"\n  Classification Report (aggregated):")
    report = classification_report(
        all_y_true, all_y_pred,
        target_names=['Benign', 'Malicious'],
        digits=4
    )
    for line in report.split('\n'):
        print(f"  {line}")

    return {
        'fold_results': fold_results,
        'avg_accuracy': avg_acc,
        'avg_precision': avg_prec,
        'avg_recall': avg_rec,
        'avg_f1': avg_f1,
        'std_accuracy': std_acc,
        'y_true': np.array(all_y_true),
        'y_pred': np.array(all_y_pred),
        'y_proba': np.array(all_y_proba),
    }


# ============================================================
# 8. VISUALIZATION
# ============================================================

def setup_plot_style():
    """Set up consistent, publication-quality plot styling."""
    plt.rcParams.update({
        'font.family': 'serif',
        'font.size': 12,
        'axes.labelsize': 13,
        'axes.titlesize': 14,
        'figure.facecolor': 'white',
        'axes.facecolor': 'white',
        'axes.grid': True,
        'grid.alpha': 0.3,
    })


def plot_confusion_matrix(y_true, y_pred, experiment_name, save_path):
    """Plot and save a confusion matrix heatmap."""
    setup_plot_style()
    cm = confusion_matrix(y_true, y_pred)

    fig, ax = plt.subplots(figsize=(7, 6))
    sns.heatmap(
        cm, annot=True, fmt='d', cmap='Blues',
        xticklabels=['Benign', 'Malicious'],
        yticklabels=['Benign', 'Malicious'],
        annot_kws={'size': 16, 'weight': 'bold'},
        linewidths=0.5, linecolor='white',
        ax=ax,
    )
    ax.set_xlabel('Predicted Label', fontsize=13)
    ax.set_ylabel('True Label', fontsize=13)
    ax.set_title(f'Confusion Matrix\n{experiment_name}', fontsize=14,
                 fontweight='bold')

    # Add accuracy annotation
    total = cm.sum()
    correct = cm[0, 0] + cm[1, 1]
    acc = correct / total * 100
    ax.text(0.5, -0.15, f'Accuracy: {acc:.2f}%',
            transform=ax.transAxes, ha='center', fontsize=12,
            style='italic', color='#333333')

    plt.tight_layout()
    plt.savefig(save_path, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"  ✓ Saved: {os.path.basename(save_path)}")


def plot_roc_curve(y_true, y_proba, experiment_name, save_path):
    """Plot and save an ROC curve with AUC."""
    setup_plot_style()
    fpr, tpr, _ = roc_curve(y_true, y_proba)
    roc_auc = auc(fpr, tpr)

    fig, ax = plt.subplots(figsize=(8, 6))
    ax.plot(fpr, tpr, color='#1565C0', lw=2.5,
            label=f'M-FastText-2 (AUC = {roc_auc:.4f})')
    ax.plot([0, 1], [0, 1], color='#BDBDBD', lw=1.5, linestyle='--',
            label='Random Classifier (AUC = 0.5000)')
    ax.fill_between(fpr, tpr, alpha=0.08, color='#1565C0')

    ax.set_xlabel('False Positive Rate (FPR)', fontsize=13)
    ax.set_ylabel('True Positive Rate (TPR)', fontsize=13)
    ax.set_title(f'ROC Curve\n{experiment_name}', fontsize=14,
                 fontweight='bold')
    ax.legend(loc='lower right', fontsize=11, framealpha=0.9)
    ax.set_xlim([-0.02, 1.02])
    ax.set_ylim([-0.02, 1.02])

    plt.tight_layout()
    plt.savefig(save_path, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"  ✓ Saved: {os.path.basename(save_path)}")


def plot_comparison(results_original, results_mixed, save_path):
    """Plot a comparison bar chart of both experiments."""
    setup_plot_style()

    metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
    orig_vals = [
        results_original['avg_accuracy'],
        results_original['avg_precision'],
        results_original['avg_recall'],
        results_original['avg_f1'],
    ]
    mixed_vals = [
        results_mixed['avg_accuracy'],
        results_mixed['avg_precision'],
        results_mixed['avg_recall'],
        results_mixed['avg_f1'],
    ]

    x = np.arange(len(metrics))
    width = 0.32

    fig, ax = plt.subplots(figsize=(10, 6))
    bars1 = ax.bar(x - width / 2, orig_vals, width,
                   label='Original Dataset (malicious_pure)',
                   color='#1565C0', alpha=0.88, edgecolor='white')
    bars2 = ax.bar(x + width / 2, mixed_vals, width,
                   label='Mixed Dataset (mixed_malicious)',
                   color='#FF8F00', alpha=0.88, edgecolor='white')

    ax.set_ylabel('Score', fontsize=13)
    ax.set_title('M-FastText-2 Performance Comparison\n'
                 '(5-Fold Cross-Validation)', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(metrics, fontsize=12)
    ax.legend(fontsize=10, loc='lower left')

    # Dynamic y-axis range
    all_vals = orig_vals + mixed_vals
    y_min = max(0, min(all_vals) - 0.05)
    y_max = min(1.0, max(all_vals) + 0.02)
    ax.set_ylim(y_min, y_max)

    # Value labels on bars
    for bar in bars1:
        h = bar.get_height()
        ax.annotate(f'{h:.4f}',
                    xy=(bar.get_x() + bar.get_width() / 2, h),
                    xytext=(0, 4), textcoords="offset points",
                    ha='center', va='bottom', fontsize=9, fontweight='bold')
    for bar in bars2:
        h = bar.get_height()
        ax.annotate(f'{h:.4f}',
                    xy=(bar.get_x() + bar.get_width() / 2, h),
                    xytext=(0, 4), textcoords="offset points",
                    ha='center', va='bottom', fontsize=9, fontweight='bold')

    plt.tight_layout()
    plt.savefig(save_path, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"  ✓ Saved: {os.path.basename(save_path)}")


def plot_fold_details(results, experiment_name, save_path):
    """Plot per-fold accuracy as a bar chart."""
    setup_plot_style()

    folds = [r['fold'] for r in results['fold_results']]
    accs = [r['accuracy'] for r in results['fold_results']]

    fig, ax = plt.subplots(figsize=(8, 5))
    colors = ['#1565C0', '#1976D2', '#1E88E5', '#2196F3', '#42A5F5']
    bars = ax.bar(folds, accs, color=colors, alpha=0.88, edgecolor='white',
                  width=0.6)

    ax.axhline(y=results['avg_accuracy'], color='#C62828', linestyle='--',
               lw=1.5, label=f'Mean = {results["avg_accuracy"]:.4f}')

    for bar, acc in zip(bars, accs):
        ax.annotate(f'{acc:.4f}',
                    xy=(bar.get_x() + bar.get_width() / 2, acc),
                    xytext=(0, 5), textcoords="offset points",
                    ha='center', va='bottom', fontsize=10, fontweight='bold')

    ax.set_xlabel('Fold', fontsize=13)
    ax.set_ylabel('Accuracy', fontsize=13)
    ax.set_title(f'Per-Fold Accuracy\n{experiment_name}', fontsize=14,
                 fontweight='bold')
    ax.set_xticks(folds)
    ax.legend(fontsize=11)

    y_min = max(0, min(accs) - 0.03)
    ax.set_ylim(y_min, 1.005)

    plt.tight_layout()
    plt.savefig(save_path, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"  ✓ Saved: {os.path.basename(save_path)}")


# ============================================================
# 9. MAIN EXECUTION
# ============================================================

def main():
    print()
    print("╔" + "═" * 63 + "╗")
    print("║  M-FastText-2: Malicious PowerShell Script Detection          ║")
    print("║  Paper: Fang et al., Neurocomputing 2021                      ║")
    print("║  Model: FastText(300d, skip-gram, 2-grams) + Random Forest    ║")
    print("╚" + "═" * 63 + "╝")

    start_time = time.time()

    # Create results directory
    os.makedirs(RESULTS_DIR, exist_ok=True)

    # ================================================================
    # Phase 1: Load Dataset
    # ================================================================
    print("\n[Phase 1] Loading dataset...")

    malicious_scripts, mal_files = load_scripts(
        MALICIOUS_DIR, "  Loading malicious_pure"
    )
    mixed_scripts, mix_files = load_scripts(
        MIXED_DIR, "  Loading mixed_malicious"
    )
    benign_scripts, ben_files = load_scripts(
        BENIGN_DIR, "  Loading powershell_benign"
    )

    # Filter out empty scripts
    malicious_scripts_clean = [s for s in malicious_scripts if len(s.strip()) > 0]
    mixed_scripts_clean = [s for s in mixed_scripts if len(s.strip()) > 0]
    benign_scripts_clean = [s for s in benign_scripts if len(s.strip()) > 0]

    print(f"\n  Dataset Summary (after filtering empty):")
    print(f"    malicious_pure:     {len(malicious_scripts_clean):>5} scripts")
    print(f"    mixed_malicious:    {len(mixed_scripts_clean):>5} scripts")
    print(f"    powershell_benign:  {len(benign_scripts_clean):>5} scripts")

    if len(malicious_scripts_clean) == 0:
        print("\n  [ERROR] No malicious scripts could be loaded!")
        print("  Please disable Windows Defender real-time protection or add")
        print("  an exclusion for the mpsd folder.")
        sys.exit(1)

    # ================================================================
    # Phase 2: Discover Top Tokens (Section 3.2.2)
    # ================================================================
    all_scripts_for_tokens = malicious_scripts_clean + benign_scripts_clean
    top_functions_scores, top_members = discover_top_tokens(
        malicious_scripts_clean,
        benign_scripts_clean,
        all_scripts_for_tokens,
        k_functions=TOP_K_FUNCTIONS,
        k_members=TOP_K_MEMBERS,
    )
    
    # Save tokens definition (scores for functions, list for members)
    tokens_path = os.path.join(RESULTS_DIR, "top_tokens_78dim.json")
    with open(tokens_path, 'w', encoding='utf-8') as f:
        json.dump({
            "top_functions_scores": top_functions_scores,
            "top_members": top_members
        }, f)
    print(f"  ✓ Saved token definitions to {tokens_path}")

    # ================================================================
    # Phase 3: Train FastText (Section 3.3.3)
    # ================================================================
    fasttext_model = train_fasttext_model(all_scripts_for_tokens)

    # ================================================================
    # Phase 4: Extract Hybrid Features
    # ================================================================
    print("\n[Phase 4] Extracting hybrid features...")

    # --- Experiment 1: Original Dataset ---
    print("\n  ── Experiment 1: Original Dataset ──")
    X_orig_mal = extract_all_features(malicious_scripts_clean, fasttext_model,
                                      top_functions_scores, top_members,
                                      desc="  Extracting malicious")
    X_orig_ben = extract_all_features(benign_scripts_clean, fasttext_model,
                                      top_functions_scores, top_members,
                                      desc="  Extracting original benign")

    X_original = np.vstack([X_orig_mal, X_orig_ben])
    y_original = np.array(
        [1] * len(X_orig_mal) + [0] * len(X_orig_ben)
    )
    print(f"  Original dataset shape: {X_original.shape}")

    # --- Experiment 2: Mixed Dataset ---
    print("\n  ── Experiment 2: Mixed Dataset ──")
    X_mix_mal = extract_all_features(
        mixed_scripts_clean, fasttext_model,
        top_functions_scores, top_members,
        desc="  Features (mixed_malicious)"
    )

    X_mixed = np.vstack([X_mix_mal, X_orig_ben])
    y_mixed = np.array(
        [1] * len(X_mix_mal) + [0] * len(X_orig_ben)
    )
    print(f"  Mixed dataset shape: {X_mixed.shape}")

    # Feature dimension summary
    feat_dim = 78
    print(f"\n  Feature Vector Breakdown (per script):")
    print(f"  ┌──────────────────────────────┬──────┐")
    print(f"  │ FastText (simulated output)   │    2 │")
    print(f"  │ Textual features (§3.2.1)     │   13 │")
    print(f"  │ Token features (§3.2.2)       │   34 │")
    print(f"  │   └─ Total functions rating   │    1 │")
    print(f"  │   └─ Top 33 member ratios     │   33 │")
    print(f"  │ AST features (§3.2.3)         │   29 │")
    print(f"  │   └─ 23 main nodes            │   23 │")
    print(f"  │   └─ 5 special nodes          │    5 │")
    print(f"  │   └─ AST depth                │    1 │")
    print(f"  ├──────────────────────────────┼──────┤")
    print(f"  │ TOTAL                         │  {feat_dim:>3} │")
    print(f"  └──────────────────────────────┴──────┘")

    # ================================================================
    # Phase 5: Run Experiments (Section 3.4)
    # ================================================================
    print("\n[Phase 5] Training & evaluating Random Forest...")
    print(f"  RF: n_estimators={RF_N_ESTIMATORS}, "
          f"max_features={RF_MAX_FEATURES}, "
          f"random_state={RF_RANDOM_STATE}")
    print(f"  CV: {N_FOLDS}-fold stratified cross-validation")

    results_original = run_experiment(
        X_original, y_original,
        "Experiment 1: Original (malicious_pure vs benign)"
    )

    results_mixed = run_experiment(
        X_mixed, y_mixed,
        "Experiment 2: Mixed (mixed_malicious vs benign)"
    )

    # ================================================================
    # Phase 6: Generate Visualizations
    # ================================================================
    print("\n[Phase 6] Generating visualizations...")

    # Confusion Matrices
    plot_confusion_matrix(
        results_original['y_true'], results_original['y_pred'],
        "Original Dataset", 
        os.path.join(RESULTS_DIR, "confusion_matrix_original.png")
    )
    plot_confusion_matrix(
        results_mixed['y_true'], results_mixed['y_pred'],
        "Mixed Dataset",
        os.path.join(RESULTS_DIR, "confusion_matrix_mixed.png")
    )

    # ROC Curves
    plot_roc_curve(
        results_original['y_true'], results_original['y_proba'],
        "Original Dataset",
        os.path.join(RESULTS_DIR, "roc_curve_original.png")
    )
    plot_roc_curve(
        results_mixed['y_true'], results_mixed['y_proba'],
        "Mixed Dataset",
        os.path.join(RESULTS_DIR, "roc_curve_mixed.png")
    )

    # Per-fold accuracy charts
    plot_fold_details(
        results_original, "Original Dataset",
        os.path.join(RESULTS_DIR, "fold_accuracy_original.png")
    )
    plot_fold_details(
        results_mixed, "Mixed Dataset",
        os.path.join(RESULTS_DIR, "fold_accuracy_mixed.png")
    )

    # Comparison chart
    plot_comparison(
        results_original, results_mixed,
        os.path.join(RESULTS_DIR, "performance_comparison.png")
    )

    # ================================================================
    # Final Summary
    # ================================================================
    elapsed = time.time() - start_time

    print(f"\n{'═' * 65}")
    print(f"  FINAL RESULTS SUMMARY")
    print(f"{'═' * 65}")
    print(f"\n  ┌─────────────────────────┬────────────┬────────────┐")
    print(f"  │ Metric                  │  Original  │   Mixed    │")
    print(f"  ├─────────────────────────┼────────────┼────────────┤")
    print(f"  │ Accuracy                │ "
          f"{results_original['avg_accuracy']:.4f}     │ "
          f"{results_mixed['avg_accuracy']:.4f}     │")
    print(f"  │ Precision               │ "
          f"{results_original['avg_precision']:.4f}     │ "
          f"{results_mixed['avg_precision']:.4f}     │")
    print(f"  │ Recall                  │ "
          f"{results_original['avg_recall']:.4f}     │ "
          f"{results_mixed['avg_recall']:.4f}     │")
    print(f"  │ F1-Score                │ "
          f"{results_original['avg_f1']:.4f}     │ "
          f"{results_mixed['avg_f1']:.4f}     │")
    print(f"  └─────────────────────────┴────────────┴────────────┘")
    print(f"\n  Paper's reported results:")
    print(f"    Experiment 1 (Original): Accuracy ≈ 98.93%")
    print(f"    Experiment 2 (Mixed):    Accuracy ≈ 97.76%")
    print(f"\n  Execution time: {elapsed:.1f}s ({elapsed/60:.1f} min)")
    print(f"  Results saved to: {RESULTS_DIR}")
    print(f"\n  Generated files:")
    for f in sorted(os.listdir(RESULTS_DIR)):
        fpath = os.path.join(RESULTS_DIR, f)
        size_kb = os.path.getsize(fpath) / 1024
        print(f"    • {f} ({size_kb:.1f} KB)")

    print(f"\n{'═' * 65}")

    # ================================================================
    # Phase 7: Train & Save Final Model (for inference)
    # ================================================================
    print("\n[Phase 7] Training & saving final model for future inference...")
    
    # Simulate FastText 2D output for the entire original dataset
    X_orig_ft = X_original[:, :FASTTEXT_DIM]
    X_orig_manual = X_original[:, FASTTEXT_DIM:]
    
    final_ft_clf = LogisticRegression(random_state=RF_RANDOM_STATE, max_iter=1000)
    final_ft_clf.fit(X_orig_ft, y_original)
    
    y_orig_ft_pred = final_ft_clf.predict(X_orig_ft).reshape(-1, 1)
    y_orig_ft_proba = final_ft_clf.predict_proba(X_orig_ft)[:, 1].reshape(-1, 1)
    
    X_orig_final = np.hstack([y_orig_ft_pred, y_orig_ft_proba, X_orig_manual])
    
    # Train final Random Forest on the entire 78D original dataset
    final_rf = RandomForestClassifier(
        n_estimators=RF_N_ESTIMATORS,
        max_features=RF_MAX_FEATURES,
        random_state=RF_RANDOM_STATE,
        n_jobs=-1,
    )
    final_rf.fit(X_orig_final, y_original)
    
    # Save FastText embedding model
    fasttext_path = os.path.join(RESULTS_DIR, "m_fasttext2.model")
    fasttext_model.save(fasttext_path)
    
    # Save simulated FastText Logistic Regression model
    ft_clf_path = os.path.join(RESULTS_DIR, "ft_classifier.pkl")
    with open(ft_clf_path, 'wb') as f:
        pickle.dump(final_ft_clf, f)
    
    # Save Random Forest model
    rf_path = os.path.join(RESULTS_DIR, "rf_classifier.pkl")
    with open(rf_path, 'wb') as f:
        pickle.dump(final_rf, f)
        
    # Save Top Tokens (needed for feature extraction later)
    tokens_path = os.path.join(RESULTS_DIR, "top_tokens_78dim.json")
    with open(tokens_path, 'w') as f:
        json.dump({
            "top_functions_scores": top_functions_scores,
            "top_members": top_members
        }, f)
        
    print(f"  ✓ Saved FastText embedding model: {os.path.basename(fasttext_path)}")
    print(f"  ✓ Saved FastText simulated classifier: {os.path.basename(ft_clf_path)}")
    print(f"  ✓ Saved Random Forest classifier: {os.path.basename(rf_path)}")
    print(f"  ✓ Saved Token configuration:      {os.path.basename(tokens_path)}")
    print(f"  (You can now use these files to predict new scripts without retraining!)")


if __name__ == "__main__":
    main()
