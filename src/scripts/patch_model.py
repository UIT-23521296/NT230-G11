import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))

base_file = os.path.join(BASE_DIR, "src", "core", "m_fasttext2_model_78dim.py")
out_file = os.path.join(BASE_DIR, "src", "core", "m_fasttext2_model_enhanced.py")

with open(base_file, "r", encoding="utf-8") as f:
    content = f.read()

# 1. Update Results Dir
content = content.replace('RESULTS_DIR = os.path.join(BASE_DIR, "results", "78dim")', 'RESULTS_DIR = os.path.join(BASE_DIR, "results", "enhanced")')

# 2. Add Win32 API features function right before extract_all_features
win32_func = """
# ============================================================
# NEW CONTRIBUTION: BEHAVIORAL WIN32 API FEATURES
# ============================================================
def extract_win32_api_features(script):
    \"\"\"
    New Contribution: Win32 API and Behavioral Indicators (Post-Exploitation).
    Detects low-level API calls used heavily by pentesting tools like PowerSploit/Empire
    for Reflective PE Injection, Memory Allocation, and AMSI/ETW patching.
    \"\"\"
    apis = [
        r'VirtualAlloc',
        r'CreateThread',
        r'WriteProcessMemory',
        r'LoadLibrary',
        r'GetProcAddress',
        r'AmsiScanBuffer',
        r'EtwEventWrite',
        r'Add-Type',
        r'DllImport',
        r'System\.Reflection',
        r'System\.Runtime\.InteropServices',
        r'Net\.Sockets',
        r'Security\.Cryptography'
    ]
    script_lower = script.lower()
    features = []
    for api in apis:
        count = len(re.findall(api.lower(), script_lower))
        features.append(count)
    return features

# ============================================================
# 6. FEATURE EXTRACTION PIPELINE
# ============================================================
"""
content = content.replace("# ============================================================\n# 6. FEATURE EXTRACTION PIPELINE\n# ============================================================", win32_func)

# 3. Update extract_all_features to include it
old_extract = """        # AST features (29 dim) - Section 3.2.3
        ast = extract_ast_features(script)

        # Concatenate all features
        feature_vector = np.concatenate([
            embedding,
            np.array(textual, dtype=np.float64),
            np.array(token, dtype=np.float64),
            np.array(ast, dtype=np.float64),
        ])"""

new_extract = """        # AST features (29 dim) - Section 3.2.3
        ast = extract_ast_features(script)
        
        # Win32 API Features (13 dim) - NEW CONTRIBUTION
        win32 = extract_win32_api_features(script)

        # Concatenate all features
        feature_vector = np.concatenate([
            embedding,
            np.array(textual, dtype=np.float64),
            np.array(token, dtype=np.float64),
            np.array(ast, dtype=np.float64),
            np.array(win32, dtype=np.float64),
        ])"""

content = content.replace(old_extract, new_extract)

with open(out_file, "w", encoding="utf-8") as f:
    f.write(content)

print("Created m_fasttext2_model_enhanced.py")
