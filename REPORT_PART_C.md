# Báo Cáo Phần C: Thu Thập Và Đánh Giá Trên Tập Dữ Liệu Mới

## 1. Mục tiêu

Phần C yêu cầu thu thập thêm **01 tập dữ liệu mới** về mã độc PowerShell, sau đó sử dụng mô hình M-FastText-2 đã huấn luyện ở Phần B để đánh giá trên tập dữ liệu mới này. Mục đích là kiểm tra **khả năng tổng quát hóa (generalization)** của mô hình — tức mô hình có thể phát hiện được mã độc PowerShell từ các nguồn hoàn toàn mới, chưa từng xuất hiện trong quá trình huấn luyện hay không.

## 2. Nguồn Dữ Liệu Mới

Tất cả dữ liệu được thu thập từ các repository **công khai và miễn phí** trên GitHub.

### 2.1. Dữ liệu mã độc (Malicious)

| # | Repository | Số lượng | Mô tả | URL |
|---|-----------|----------|-------|-----|
| 1 | **PowerSploit** | 43 scripts | Bộ công cụ tấn công PowerShell nổi tiếng, gồm các module cho code execution, persistence, recon | https://github.com/PowerShellMafia/PowerSploit |
| 2 | **Nishang** | 89 scripts | Framework PowerShell cho offensive security và penetration testing | https://github.com/samratashok/nishang |
| 3 | **Invoke-Obfuscation** | 15 scripts | Công cụ obfuscation (mã hóa/che giấu) lệnh PowerShell, dùng để qua mặt hệ thống phát hiện | https://github.com/danielbohannon/Invoke-Obfuscation |
| 4 | **Empire** | 162 scripts | Framework C2 (Command & Control) sử dụng PowerShell agents | https://github.com/BC-SECURITY/Empire |
| | **Tổng Malicious** | **309 scripts** | | |

### 2.2. Dữ liệu an toàn (Benign)

| # | Repository | Số lượng | Mô tả | URL |
|---|-----------|----------|-------|-----|
| 5 | **fleschutz/PowerShell** | 680 scripts | Hơn 600 script quản trị hệ thống, tự động hóa, tiện ích CLI | https://github.com/fleschutz/PowerShell |
| 6 | **PSSysadminToolkit** | 33 scripts | Bộ toolkit PowerShell dành cho System Administrator | https://github.com/steviecoaster/PSSysadminToolkit |
| | **Tổng Benign** | **713 scripts** | | |

### 2.3. So sánh với tập dữ liệu gốc

| Đặc điểm | Tập gốc (MPSD) | Tập mới |
|-----------|----------------|---------|
| Nguồn gốc | Bài báo Fang et al. 2021 | Thu thập từ GitHub (2024-2026) |
| Tổng số mẫu | 8,518 | 1,022 |
| Mã độc | Thu thập từ malware databases, sandbox | Công cụ pentesting thực tế (attack tools) |
| An toàn | PowerShell Gallery | System admin scripts (sysadmin tools) |
| Đặc điểm mã độc | Script mã độc thuần túy + biến thể obfuscated | Công cụ tấn công chuyên nghiệp, module hóa |
| Kiểu viết mã độc | Obfuscated, encoded, shellcode, download payload | Clean code, có documentation, function structure |

> **Điểm khác biệt cốt lõi:** Tập mới chứa mã độc từ các công cụ penetration testing thực tế (PowerSploit, Nishang, Empire). Đây là những công cụ mà hacker sử dụng trong thực tế, nhưng chúng được viết theo phong cách **module phần mềm chuyên nghiệp** — có comment, có help text, có cấu trúc function rõ ràng — hoàn toàn khác với mã độc "thô" trong tập huấn luyện gốc.

## 3. Quy Trình Thực Hiện

### Bước 1: Thu thập dữ liệu
```bash
python collect_new_dataset.py
```
Script tự động:
- Clone các repository với `git clone --depth 1` (chỉ lấy phiên bản mới nhất)
- Quét đệ quy tìm tất cả file `.ps1` và `.psm1`
- Lọc bỏ file quá nhỏ (< 50 bytes)
- Tổ chức vào cấu trúc `new_dataset/malicious/` và `new_dataset/benign/`

### Bước 2: Đánh giá mô hình
```bash
python evaluate_new_dataset.py
```
Script tự động:
- Load mô hình đã train (FastText embedding + Random Forest classifier + Token config)
- Trích xuất 574 đặc trưng hybrid cho mỗi script trong tập mới
- Dự đoán nhãn (malicious/benign) cho mỗi script
- Tính toán các chỉ số: Accuracy, Precision, Recall, F1-Score, AUC
- Xuất biểu đồ Confusion Matrix, ROC Curve, và biểu đồ so sánh

## 4. Kết Quả

### 4.1. Thống kê tập dữ liệu mới

| Loại | Số lượng | Tỷ lệ | Nguồn |
|------|----------|--------|-------|
| Malicious | 309 | 30.2% | PowerSploit (43), Nishang (89), Invoke-Obfuscation (15), Empire (162) |
| Benign | 713 | 69.8% | fleschutz/PowerShell (680), PSSysadminToolkit (33) |
| **Tổng** | **1,022** | 100% | 6 repositories từ GitHub |

### 4.2. Kết quả đánh giá trên tập mới

| Metric | Tập gốc (Original) | Tập gốc (Mixed) | **Tập mới** |
|--------|--------------------:|----------------:|------------:|
| Accuracy | 98.54% | 95.57% | **76.52%** |
| Precision | 99.42% | 97.99% | **97.26%** |
| Recall | 97.62% | 92.93% | **22.98%** |
| F1-Score | 98.51% | 95.40% | **37.17%** |
| AUC | — | — | **0.6523** |

### 4.3. Ma trận nhầm lẫn (Confusion Matrix)

|  | Dự đoán: Benign | Dự đoán: Malicious |
|--|----------------:|------------------:|
| **Thực tế: Benign** | **711** (True Negative) | 2 (False Positive) |
| **Thực tế: Malicious** | 238 (False Negative) | **71** (True Positive) |

**Tổng mẫu phân loại đúng:** 782/1022 = 76.52%

### 4.4. Biểu đồ

Các biểu đồ được lưu tại thư mục `results/`:
- `confusion_matrix_new_dataset.png` — Ma trận nhầm lẫn trên tập mới
- `roc_curve_new_dataset.png` — Đường cong ROC trên tập mới (AUC = 0.6523)
- `comparison_new_dataset.png` — So sánh hiệu suất: bài báo vs tập mới

## 5. Phân Tích Kết Quả

### 5.1. Tổng quan

Kết quả cho thấy mô hình M-FastText-2 có **Precision rất cao (97.26%)** nhưng **Recall cực thấp (22.98%)** trên tập dữ liệu mới. Điều này có nghĩa:

- ✅ Khi mô hình **nói một script là mã độc**, thì **97.26% là đúng** → hầu như không bắt nhầm file an toàn.
- ❌ Nhưng mô hình **bỏ sót tới 77% mã độc** (238/309 mã độc bị phân loại sai thành benign).
- ✅ Mô hình nhận diện **99.72% script benign chính xác** (711/713).

### 5.2. Nguyên nhân Recall thấp — Phân tích chi tiết

#### Nguyên nhân 1: Sự khác biệt bản chất giữa "mã độc thuần túy" và "công cụ tấn công" (Domain Shift)

Đây là nguyên nhân **quan trọng nhất**. Tập dữ liệu huấn luyện (MPSD) và tập dữ liệu mới chứa hai loại mã độc có bản chất rất khác nhau:

| Đặc điểm | Mã độc trong MPSD (tập train) | Mã độc mới (pentesting tools) |
|-----------|-------------------------------|-------------------------------|
| **Mục đích** | Script tấn công trực tiếp (dropper, payload) | Công cụ hỗ trợ tấn công (framework, module) |
| **Phong cách code** | Obfuscated, encoded, ngắn gọn, khó đọc | Clean code, có documentation, function rõ ràng |
| **Cấu trúc** | Script đơn lẻ, chạy một lần | Module hoàn chỉnh với `param()`, `help`, `export` |
| **Entropy** | Cao (do mã hóa/obfuscation) | Thấp-Trung bình (code dễ đọc) |
| **Shellcode** | Thường có (hex bytes, base64) | Ít khi có trực tiếp trong source |
| **URL/IP** | Thường chứa C2 server address | Ít chứa trong code nguồn |

**Ví dụ minh hoạ sự khác biệt:**

Mã độc trong MPSD thường trông như thế này:
```powershell
# Obfuscated, khó đọc, entropy cao
$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String("H4sIAAAA..."));
IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()
```

Trong khi mã độc từ PowerSploit/Nishang trông giống phần mềm chuyên nghiệp:
```powershell
function Invoke-Mimikatz {
    <#
    .SYNOPSIS
    Reflectively loads Mimikatz into memory using PowerShell.
    
    .DESCRIPTION
    This script leverages reflective loading to run Mimikatz entirely
    in-memory without touching disk.
    
    .PARAMETER DumpCreds
    Switch to dump credentials from LSASS.
    #>
    [CmdletBinding()]
    Param(
        [Switch]$DumpCreds,
        [String]$ComputerName
    )
    # ... proper function body with error handling ...
}
```

→ Mô hình được huấn luyện để nhận diện **các dấu hiệu bề mặt** (obfuscation, shellcode, URL) nên bỏ sót mã độc "trông sạch sẽ".

#### Nguyên nhân 2: Đặc trưng Textual (12 features) không bắt được mã độc "sạch"

Trong 12 đặc trưng textual, nhiều feature dựa vào **dấu hiệu obfuscation**:
- **Shellcode existence (0/1):** Pentesting tools không nhúng shellcode trực tiếp → feature = 0 (giống benign)
- **Information Entropy:** Code sạch có entropy thấp → giống benign
- **URL/IP existence (0/1):** Pentesting tools không hardcode C2 address → feature = 0 (giống benign)
- **Special variable count:** Pentesting tools dùng tên biến chuyên nghiệp, không phải `$cmd`, `$Shell` → count thấp

#### Nguyên nhân 3: Đặc trưng Token (233 features) bị lệch phân phối

Top 200 functions và Top 33 member tokens được học từ tập MPSD. Các function phổ biến trong mã độc MPSD (ví dụ: `Invoke-Expression`, `DownloadString`, `FromBase64String`) có thể không xuất hiện nhiều trong pentesting tools đã được module hóa. Ngược lại, pentesting tools sử dụng nhiều cmdlet phức tạp hơn (`Get-WmiObject`, `Add-Type`, `New-Object`) mà tập train có thể không đánh dấu là đặc trưng mã độc.

#### Nguyên nhân 4: FastText Embedding (300 dim) học được ngữ nghĩa từ tập train

Mô hình FastText được train trên corpus MPSD. Các vector nhúng (word embeddings) phản ánh ngữ nghĩa của **tập MPSD**, không phải ngữ nghĩa chung. Khi gặp từ vựng và cấu trúc câu mới từ pentesting tools, embedding có thể không phân biệt được malicious vs benign.

### 5.3. Tại sao Precision vẫn rất cao (97.26%)?

Precision cao cho thấy: trong 309 mã độc mới, có khoảng **71 script** vẫn mang đặc điểm "mã độc truyền thống" (có shellcode, obfuscation, hoặc sử dụng các function/member nguy hiểm) → mô hình vẫn bắt đúng. Chỉ có **2 script benign** bị bắt nhầm → rất ít false positive.

Điều này chứng tỏ mô hình **rất bảo thủ** (conservative): nó chỉ đánh dấu malicious khi **rất chắc chắn**, nên hầu như không bắt nhầm, nhưng cái giá phải trả là bỏ sót nhiều.

### 5.4. Ý nghĩa học thuật

Kết quả này minh họa rõ ràng khái niệm **Distribution Shift** (Dịch chuyển phân phối) trong Machine Learning:

> Khi phân phối dữ liệu kiểm thử (test distribution) khác biệt đáng kể so với phân phối dữ liệu huấn luyện (train distribution), hiệu suất mô hình sẽ suy giảm — ngay cả khi mô hình đạt kết quả xuất sắc trên tập test gốc.

Đây cũng là **điểm yếu cố hữu** của mô hình dựa trên đặc trưng thủ công (manual features): chúng phụ thuộc mạnh vào các "dấu hiệu" đã biết từ trước. Mã độc ngày càng tinh vi, viết giống phần mềm hợp pháp, khiến các đặc trưng bề mặt trở nên vô hiệu.

## 6. Đề Xuất Cải Thiện

Dựa trên phân tích, có thể cải thiện mô hình theo các hướng:

1. **Mở rộng tập huấn luyện:** Thêm mã độc từ pentesting tools (PowerSploit, Empire, Nishang) vào tập train để mô hình học được các đặc điểm mã độc đa dạng hơn.

2. **Thêm đặc trưng hành vi (behavioral features):** Phân tích hành vi tiềm ẩn của script (VD: có load DLL hay không, có truy cập registry nguy hiểm hay không) thay vì chỉ dựa vào dấu hiệu bề mặt.

3. **Sử dụng mô hình Deep Learning:** Các mô hình như BERT hoặc transformer có thể học ngữ nghĩa sâu hơn, phân biệt tốt hơn giữa code "trông sạch nhưng nguy hiểm" và code thật sự an toàn.

4. **Ensemble với nhiều tập dữ liệu:** Kết hợp huấn luyện trên nhiều nguồn dữ liệu khác nhau (malware databases + pentesting tools + in-the-wild samples) để tăng khả năng tổng quát hóa.

## 7. Kết Luận

- Mô hình M-FastText-2 **hoạt động xuất sắc** trên dữ liệu cùng phân phối (Accuracy ~98.54% trên tập gốc MPSD).
- Khi áp dụng lên **dữ liệu mới từ nguồn khác**, hiệu suất giảm đáng kể (Accuracy 76.52%, Recall 22.98%) do **sự khác biệt bản chất giữa hai loại mã độc**.
- Precision vẫn giữ ở mức rất cao (97.26%), cho thấy mô hình **không bắt nhầm** file an toàn.
- Kết quả này đặt ra câu hỏi quan trọng về **khả năng tổng quát hóa** của các mô hình phát hiện mã độc dựa trên đặc trưng tĩnh, và gợi mở hướng nghiên cứu tiếp theo.

## 8. Cấu trúc thư mục

```
Do An/
├── m_fasttext2_model.py       # Mô hình chính (Phần B)
├── reproduce_table3.py        # Tái tạo Table 3 (Phần B)
├── collect_new_dataset.py     # Thu thập dữ liệu mới (Phần C)
├── evaluate_new_dataset.py    # Đánh giá trên tập mới (Phần C)
├── REPORT_PART_C.md           # Báo cáo phần C (file này)
├── requirements.txt
├── mpsd/                      # Tập dữ liệu gốc (Phần A)
├── new_dataset/               # Tập dữ liệu mới (Phần C)
│   ├── malicious/    (309 files)
│   ├── benign/       (713 files)
│   └── dataset_info.txt
└── results/                   # Toàn bộ kết quả
    ├── confusion_matrix_original.png
    ├── confusion_matrix_mixed.png
    ├── confusion_matrix_new_dataset.png
    ├── roc_curve_original.png
    ├── roc_curve_mixed.png
    ├── roc_curve_new_dataset.png
    ├── comparison_new_dataset.png
    ├── performance_comparison.png
    ├── fold_accuracy_original.png
    ├── fold_accuracy_mixed.png
    ├── m_fasttext2.model
    ├── rf_classifier.pkl
    └── top_tokens.json
```
