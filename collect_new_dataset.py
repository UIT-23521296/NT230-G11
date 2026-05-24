"""
================================================================================
Phần C: Thu thập tập dữ liệu mới về mã độc PowerShell
================================================================================
Script này tự động clone các repository chứa mã độc PowerShell và script
an toàn từ GitHub, sau đó tổ chức thành một tập dữ liệu mới có cấu trúc.

Nguồn dữ liệu:
  MALICIOUS:
    1. PowerSploit      - Bộ công cụ tấn công PowerShell nổi tiếng
    2. Nishang           - Framework PowerShell cho pentesting
    3. Invoke-Obfuscation - Công cụ obfuscation PowerShell
    4. Empire (BC-SECURITY) - Framework C2 (Command & Control)
    
  BENIGN:
    5. fleschutz/PowerShell - 600+ script quản trị hệ thống
    6. PSSysadminToolkit    - Toolkit cho sysadmin

Tất cả nguồn đều miễn phí, công khai trên GitHub.
================================================================================
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path

# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
NEW_DATASET_DIR = os.path.join(BASE_DIR, "new_dataset")
CLONE_TEMP_DIR = os.path.join(BASE_DIR, "_clone_temp")

# Repositories to clone
MALICIOUS_REPOS = [
    {
        "name": "PowerSploit",
        "url": "https://github.com/PowerShellMafia/PowerSploit.git",
        "desc": "Bộ công cụ tấn công PowerShell (code execution, persistence, recon)",
    },
    {
        "name": "Nishang",
        "url": "https://github.com/samratashok/nishang.git",
        "desc": "Framework PowerShell cho offensive security & pentesting",
    },
    {
        "name": "Invoke-Obfuscation",
        "url": "https://github.com/danielbohannon/Invoke-Obfuscation.git",
        "desc": "Công cụ obfuscation PowerShell (mã hóa/che giấu lệnh)",
    },
    {
        "name": "Empire-PowerShell",
        "url": "https://github.com/BC-SECURITY/Empire.git",
        "desc": "Framework C2 (Command & Control) sử dụng PowerShell agents",
    },
]

BENIGN_REPOS = [
    {
        "name": "fleschutz-PowerShell",
        "url": "https://github.com/fleschutz/PowerShell.git",
        "desc": "600+ script quản trị hệ thống, tự động hóa, tiện ích",
    },
    {
        "name": "PSSysadminToolkit",
        "url": "https://github.com/steviecoaster/PSSysadminToolkit.git",
        "desc": "Toolkit PowerShell cho system administrator",
    },
]


# ============================================================
# FUNCTIONS
# ============================================================

def clone_repo(url, dest_dir, name):
    """Clone a git repository with shallow depth for speed."""
    if os.path.exists(dest_dir):
        print(f"    [SKIP] {name} already cloned")
        return True
    
    print(f"    Cloning {name}...")
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", url, dest_dir],
            capture_output=True, text=True, timeout=300
        )
        if result.returncode != 0:
            print(f"    [ERROR] Failed to clone {name}: {result.stderr[:200]}")
            return False
        print(f"    [OK] {name} cloned successfully")
        return True
    except subprocess.TimeoutExpired:
        print(f"    [ERROR] Timeout cloning {name}")
        return False
    except FileNotFoundError:
        print(f"    [ERROR] 'git' not found. Please install Git.")
        return False


def collect_ps1_files(source_dir, dest_dir, label_name):
    """
    Recursively find all .ps1 files in source_dir and copy them
    to dest_dir with unique naming.
    """
    ps1_files = list(Path(source_dir).rglob("*.ps1"))
    
    # Also include .psm1 (PowerShell module files) as they contain 
    # executable PowerShell code
    psm1_files = list(Path(source_dir).rglob("*.psm1"))
    all_files = ps1_files + psm1_files
    
    os.makedirs(dest_dir, exist_ok=True)
    
    copied = 0
    skipped = 0
    
    repo_name = os.path.basename(source_dir)
    
    for filepath in all_files:
        try:
            # Read file to check it's valid
            content = filepath.read_text(encoding='utf-8', errors='ignore')
            
            # Skip very small files (< 50 bytes, likely empty or just comments)
            if len(content.strip()) < 50:
                skipped += 1
                continue
            
            # Create unique filename: reponame_originalname.ps1
            safe_name = filepath.stem.replace(" ", "_")
            new_name = f"{repo_name}_{safe_name}.ps1"
            dest_path = os.path.join(dest_dir, new_name)
            
            # Handle duplicates
            counter = 1
            while os.path.exists(dest_path):
                new_name = f"{repo_name}_{safe_name}_{counter}.ps1"
                dest_path = os.path.join(dest_dir, new_name)
                counter += 1
            
            # Copy with content (not binary copy, to normalize encoding)
            with open(dest_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            copied += 1
            
        except Exception as e:
            skipped += 1
    
    return copied, skipped


def main():
    print()
    print("=" * 65)
    print("  PART C: Collecting New PowerShell Dataset")
    print("  From publicly available GitHub repositories")
    print("=" * 65)
    
    # Create directories
    mal_dest = os.path.join(NEW_DATASET_DIR, "malicious")
    ben_dest = os.path.join(NEW_DATASET_DIR, "benign")
    os.makedirs(CLONE_TEMP_DIR, exist_ok=True)
    os.makedirs(mal_dest, exist_ok=True)
    os.makedirs(ben_dest, exist_ok=True)
    
    total_mal = 0
    total_ben = 0
    source_details = []
    
    # ── Clone & collect MALICIOUS repos ──
    print("\n[1] Cloning MALICIOUS PowerShell repositories...")
    for repo in MALICIOUS_REPOS:
        clone_dir = os.path.join(CLONE_TEMP_DIR, repo["name"])
        success = clone_repo(repo["url"], clone_dir, repo["name"])
        
        if success:
            copied, skipped = collect_ps1_files(clone_dir, mal_dest, "malicious")
            total_mal += copied
            source_details.append({
                "name": repo["name"],
                "label": "Malicious",
                "desc": repo["desc"],
                "collected": copied,
                "skipped": skipped,
            })
            print(f"    Collected: {copied} scripts "
                  f"(skipped {skipped} too-small files)")
    
    # ── Clone & collect BENIGN repos ──
    print("\n[2] Cloning BENIGN PowerShell repositories...")
    for repo in BENIGN_REPOS:
        clone_dir = os.path.join(CLONE_TEMP_DIR, repo["name"])
        success = clone_repo(repo["url"], clone_dir, repo["name"])
        
        if success:
            copied, skipped = collect_ps1_files(clone_dir, ben_dest, "benign")
            total_ben += copied
            source_details.append({
                "name": repo["name"],
                "label": "Benign",
                "desc": repo["desc"],
                "collected": copied,
                "skipped": skipped,
            })
            print(f"    Collected: {copied} scripts "
                  f"(skipped {skipped} too-small files)")
    
    # ── Summary ──
    print(f"\n{'=' * 65}")
    print(f"  NEW DATASET SUMMARY")
    print(f"{'=' * 65}")
    print(f"\n  Location: {NEW_DATASET_DIR}")
    print(f"  Total Malicious scripts: {total_mal}")
    print(f"  Total Benign scripts:    {total_ben}")
    print(f"  Grand Total:             {total_mal + total_ben}")
    
    print(f"\n  Sources:")
    print(f"  {'Source':<25} {'Label':<12} {'Scripts':<10} {'Description'}")
    print(f"  {'─' * 80}")
    for s in source_details:
        print(f"  {s['name']:<25} {s['label']:<12} "
              f"{s['collected']:<10} {s['desc']}")
    
    print(f"\n  Directory Structure:")
    print(f"    new_dataset/")
    print(f"    ├── malicious/    ({total_mal} files)")
    print(f"    └── benign/       ({total_ben} files)")
    
    # Save summary to file for reference
    summary_path = os.path.join(NEW_DATASET_DIR, "dataset_info.txt")
    with open(summary_path, 'w', encoding='utf-8') as f:
        f.write("NEW POWERSHELL DATASET\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"Total Malicious: {total_mal}\n")
        f.write(f"Total Benign:    {total_ben}\n\n")
        f.write("Sources:\n")
        for s in source_details:
            f.write(f"  [{s['label']}] {s['name']} - "
                    f"{s['collected']} scripts\n")
            f.write(f"    {s['desc']}\n\n")
    
    print(f"\n  Dataset info saved to: dataset_info.txt")
    
    # Cleanup option
    print(f"\n  Temporary clone directory: {CLONE_TEMP_DIR}")
    print(f"  (You can delete _clone_temp/ after collection is complete)")
    print(f"\n{'=' * 65}")
    print(f"  DONE! Now run: python evaluate_new_dataset.py")
    print(f"{'=' * 65}")


if __name__ == "__main__":
    main()
