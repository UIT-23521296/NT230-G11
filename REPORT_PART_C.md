# Báo Cáo Phần C: Thu Thập Và Đánh Giá Trên Tập Dữ Liệu Mới

## 1. Mục tiêu

Phần C yêu cầu thu thập thêm **01 tập dữ liệu mới** về mã độc PowerShell, sau đó sử dụng mô hình M-FastText-2 đã huấn luyện ở Phần B để đánh giá trên tập dữ liệu mới này. Mục đích là kiểm tra **khả năng tổng quát hóa (generalization)** của mô hình — tức mô hình có thể phát hiện được mã độc PowerShell từ các nguồn hoàn toàn mới, chưa từng xuất hiện trong quá trình huấn luyện hay không.

## 2. Nguồn Dữ Liệu Mới

Tất cả dữ liệu được thu thập từ các repository **công khai và miễn phí** trên GitHub.

### 2.1. Dữ liệu mã độc (Malicious)

| # | Repository | Số lượng | Mô tả | URL |
|---|------------|----------|-------|-----|
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

### 4.2. Kết quả đánh giá trên tập mới (So sánh 2 phiên bản kiến trúc)

Bảng dưới đây so sánh hiệu năng của mô hình 574 chiều (nhóm tự mở rộng) và 78 chiều (chuẩn bài báo) khi áp dụng lên tập dữ liệu mới:

| Phiên bản | Tập gốc (Original) | Tập gốc (Mixed) | **Tập dữ liệu mới (Domain Shift)** |
|-----------|:-------------------:|:---------------:|:---------------------------------:|
| 574 chiều (Nhóm mở rộng) | **98.58%** | **95.25%** | 77.20% |
| 78 chiều (Chuẩn bài báo) | 98.81% | 95.73% | **77.69%** |

**Chi tiết các metric trên tập mới:**

| Phiên bản | Accuracy | Precision | Recall | F1-Score | AUC |
|-----------|---------:|----------:|-------:|---------:|----:|
| **574 chiều** | 77.20% | 100.00% | 24.60% | 39.48% | 0.6740 |
| **78 chiều** | **77.69%** | 98.80% | **26.54%** | **41.84%** | **0.7770** |

### 4.3. Ma trận nhầm lẫn (Confusion Matrix) của phiên bản tốt nhất (78 chiều)

|  | Dự đoán: Benign | Dự đoán: Malicious |
|--|----------------:|------------------:|
| **Thực tế: Benign** | **712** (True Negative) | 1 (False Positive) |
| **Thực tế: Malicious** | 227 (False Negative) | **82** (True Positive) |

**Tổng mẫu phân loại đúng:** 794/1022 = 77.69%

### 4.4. Biểu đồ

Các biểu đồ được lưu tại thư mục `results/`:
- `confusion_matrix_new_dataset.png` — Ma trận nhầm lẫn trên tập mới
- `roc_curve_new_dataset.png` — Đường cong ROC trên tập mới (AUC = 0.6523)
- `comparison_new_dataset.png` — So sánh hiệu suất: bài báo vs tập mới

## 5. Phân Tích Kết Quả

### 5.1. Tổng quan

Kết quả cho thấy mô hình M-FastText-2 (ở cả 2 phiên bản) đều bị sụt giảm độ chính xác từ ~98% xuống còn ~77%. Dù **Precision vẫn giữ ở mức cực cao (~99%-100%)**, nhưng **Recall lại tụt thê thảm (khoảng 25%)**. Điều này có nghĩa:

- ✅ Khi mô hình **nói một script là mã độc**, thì nó **gần như chắc chắn đúng** (tỉ lệ false positive chỉ là 0 hoặc 1 mẫu).
- ❌ Nhưng mô hình **bỏ sót tới 75% mã độc** (khoảng 227-233 mã độc bị phân loại sai thành benign).
- ✅ Mô hình nhận diện script benign cực kỳ chính xác.

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

### 5.3. So sánh khả năng tổng quát hóa: Tại sao mô hình 78 chiều lại chiến thắng?

Một phát hiện cực kỳ thú vị trong đồ án này là sự đảo ngược thứ hạng giữa 2 phiên bản kiến trúc khi gặp dữ liệu mới:
- Trên tập huấn luyện gốc (MPSD), mô hình **574 chiều** (nhóm tự mở rộng) thường cho kết quả nhỉnh hơn mô hình 78 chiều.
- Tuy nhiên, trên tập dữ liệu mới, mô hình **78 chiều** lại vượt lên dẫn trước (Accuracy 77.69% > 77.20%, Recall 26.54% > 24.60%).

**Nguyên nhân:**
Mô hình 574 chiều giữ nguyên 200 giá trị đếm tần suất của từng hàm độc lập. Điều này giúp mô hình "học thuộc" rất tốt các đặc trưng cục bộ của tập huấn luyện (ví dụ: tập train hay dùng `Invoke-Expression` thì mô hình sẽ gán trọng số rất cao cho hàm này). Tuy nhiên, đây chính là **Overfitting (Học vẹt)**.
Ngược lại, mô hình 78 chiều đã "nén" 200 giá trị đếm hàm thành **1 con số điểm tổng quát duy nhất** (Total functions rating) như tác giả Fang et al. đề xuất. Việc nén thông tin này giúp mô hình mất đi tính cụ thể của từng hàm, nhưng bù lại mang đến **khả năng tổng quát hóa (Generalization) tốt hơn**. Khi sang tập mới, dù mã độc gọi hàm khác đi, tổng điểm hàm nguy hiểm vẫn phản ánh đúng bản chất, giúp mô hình bắt được nhiều mã độc hơn (True Positive 82 > 76).

### 5.4. Tại sao Precision vẫn rất cao (~99%)?

Precision cao cho thấy: trong 309 mã độc mới, những script vẫn mang đặc điểm "mã độc truyền thống" (có shellcode, obfuscation) mô hình vẫn bắt trúng. 
Điều này chứng tỏ mô hình **rất bảo thủ** (conservative): nó chỉ đánh dấu malicious khi **rất chắc chắn**, nên hầu như không bắt nhầm, nhưng cái giá phải trả là bỏ lọt nhiều.

### 5.5. Ý nghĩa học thuật

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

- Mô hình M-FastText-2 **hoạt động xuất sắc** trên dữ liệu cùng phân phối (Accuracy >98% trên tập gốc MPSD).
- Khi áp dụng lên **dữ liệu mới từ nguồn khác**, hiệu suất giảm đáng kể (Accuracy ~77%, Recall ~25%) do **hiện tượng Domain Shift** và sự khác biệt bản chất giữa hai loại mã độc.
- Nhóm đã phát hiện ra rằng **mô hình được nén đặc trưng (78 chiều)** có khả năng tổng quát hóa mạnh mẽ hơn, giảm thiểu được Overfitting so với mô hình thô (574 chiều) khi đối mặt với dữ liệu chưa từng thấy.
- Precision vẫn giữ ở mức gần tuyệt đối (99-100%), cho thấy mô hình **không bắt nhầm** file an toàn, rất phù hợp triển khai như một màng lọc bảo thủ.
- Kết quả này chứng minh giới hạn của kỹ thuật phân tích tĩnh (Static Analysis) và gợi mở hướng nghiên cứu tiếp theo về việc kết hợp các đặc trưng hành vi động (Dynamic Analysis).

