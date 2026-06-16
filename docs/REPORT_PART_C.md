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
# Khó đọc
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

### 5.6. Phân tích kỹ thuật mã độc trong từng tập dữ liệu

Để hiểu sâu hơn sự khác biệt giữa hai tập dữ liệu, nhóm đã phân tích **12 kỹ thuật mã độc phổ biến** trên toàn bộ 4.202 mẫu MPSD và 309 mẫu New Dataset. Kết quả cho thấy hai tập dữ liệu đại diện cho **hai trường phái tấn công hoàn toàn khác biệt**.

#### 5.6.1. So sánh tỷ lệ sử dụng kỹ thuật giữa hai tập

| Kỹ thuật | MPSD Malicious | New Malicious | MPSD Benign | New Benign |
|----------|:--------------:|:-------------:|:-----------:|:----------:|
| **Hex/Byte Array Shellcode** | **48.9%** | 35.0% | 2.1% | 0.8% |
| **Download Payload** | **45.6%** | 17.2% | 6.0% | 7.9% |
| **Process/Memory Injection** | **48.2%** | 13.6% | 0.5% | 0.0% |
| **Reflective Loading** | 49.5% | **42.4%** | 9.8% | 3.2% |
| **Dynamic Execution (IEX)** | 14.4% | **40.8%** | 8.8% | 2.1% |
| **Base64 Encoding** | 6.5% | **38.8%** | 3.1% | 0.6% |
| **Credential Theft/Dumping** | 9.5% | **39.2%** | 14.2% | 2.1% |
| **Reconnaissance/Discovery** | 2.7% | **38.8%** | 12.3% | 6.2% |
| **Anti-Detection/Evasion** | 6.2% | **27.5%** | 1.9% | 0.7% |
| **Tick/Backtick Insertion** | 1.3% | **23.3%** | 12.3% | 5.2% |
| **String Obfuscation** | 1.1% | **18.8%** | 11.3% | 3.5% |
| **Persistence Mechanisms** | 1.8% | **15.5%** | 1.7% | 1.7% |

**Nhận xét quan trọng:**

- **MPSD thiên về "Delivery" (Chuyển tải):** Gần 50% mẫu MPSD chứa Hex shellcode, Download Payload, và Process Injection. Đây là các kỹ thuật của giai đoạn **Initial Access** — khi kẻ tấn công cần đưa mã độc vào máy nạn nhân lần đầu tiên.

- **New Dataset thiên về "Post-Exploitation" (Hậu khai thác):** Mã độc mới tập trung vào Credential Theft (39.2%), Reconnaissance (38.8%), Anti-Detection (27.5%), và Persistence (15.5%). Đây là các kỹ thuật của giai đoạn **sau khi đã xâm nhập** — khi kẻ tấn công cần duy trì quyền truy cập và di chuyển trong mạng nội bộ (Lateral Movement).

#### 5.6.2. Phân tích theo từng công cụ tấn công

| Kỹ thuật | PowerSploit | Nishang | Invoke-Obfuscation | Empire |
|----------|:-----------:|:-------:|:------------------:|:------:|
| Base64 Encoding | 34.9% | 32.6% | 6.7% | **46.3%** |
| Hex/Byte Array Shellcode | **39.5%** | 30.3% | 0.0% | **39.5%** |
| Dynamic Execution (IEX) | 44.2% | **48.3%** | 6.7% | 38.9% |
| Reflective Loading | 46.5% | 16.9% | 6.7% | **58.6%** |
| Process Injection | **20.9%** | 6.7% | 0.0% | 16.7% |
| Credential Theft | 32.6% | 41.6% | 0.0% | **43.2%** |
| Reconnaissance | **51.2%** | 38.2% | 0.0% | 39.5% |
| Anti-Detection | 18.6% | 31.5% | 6.7% | **29.6%** |

**Đặc điểm từng tool:**

- **Empire** (162 scripts): Là framework C2 toàn diện, sử dụng nhiều kỹ thuật nhất — đặc biệt là Reflective Loading (58.6%) để nạp agent vào bộ nhớ và Base64 Encoding (46.3%) để mã hóa giao tiếp C2.
- **PowerSploit** (43 scripts): Chuyên về code execution và privilege escalation. Có tỷ lệ Process Injection cao nhất (20.9%) và Reconnaissance cao nhất (51.2%).
- **Nishang** (89 scripts): Framework đa năng cho offensive security. Nổi bật với IEX (48.3%) và Credential Theft (41.6%).
- **Invoke-Obfuscation** (15 scripts): Công cụ chuyên obfuscation, nhưng bản thân code nguồn của nó lại rất "sạch" (chỉ chứa logic biến đổi chuỗi, không chứa payload).

### 5.7. Phân tích chi tiết các case bị phân loại sai (False Negative)

#### 5.7.1. Tỷ lệ phát hiện theo từng công cụ

| Công cụ | Tổng scripts | Bắt được (TP) | Bỏ lọt (FN) | Recall |
|---------|:-----------:|:------------:|:-----------:|:------:|
| **Empire** | 162 | 61 | 101 | **37.7%** |
| **PowerSploit** | 43 | 13 | 30 | **30.2%** |
| **Nishang** | 89 | 7 | 82 | **7.9%** |
| **Invoke-Obfuscation** | 15 | 1 | 14 | **6.7%** |

**Nhận xét:**

- **Empire** có Recall cao nhất (37.7%) vì nhiều module của Empire (ví dụ `Invoke-Mimikatz`, `Invoke-Shellcode`) chứa shellcode nhúng và API injection — các dấu hiệu mà mô hình đã học tốt từ MPSD.
- **Nishang** và **Invoke-Obfuscation** gần như bị bỏ sót hoàn toàn (~7%). Nishang viết code theo phong cách "giáo trình" (tutorial-style) rất sạch sẽ. Invoke-Obfuscation bản thân code nguồn chỉ chứa logic biến đổi chuỗi, không chứa payload mã độc trực tiếp.

#### 5.7.2. So sánh kỹ thuật giữa nhóm Caught (TP) và Missed (FN)

| Kỹ thuật | Caught (TP) | Missed (FN) | Chênh lệch |
|----------|:-----------:|:-----------:|:-----------:|
| **Reflective Loading** | **80.5%** | 28.6% | **+51.9%** ← Yếu tố phân biệt #1 |
| **Hex/Byte Array Shellcode** | **59.8%** | 26.0% | **+33.8%** ← Yếu tố phân biệt #2 |
| **Process/Memory Injection** | **31.7%** | 7.0% | **+24.7%** |
| **Base64 Encoding** | **54.9%** | 33.0% | **+21.8%** |
| **Dynamic Execution (IEX)** | **56.1%** | 35.2% | **+20.9%** |
| **Anti-Detection/Evasion** | **42.7%** | 22.0% | **+20.7%** |
| Download Payload | 6.1% | **21.1%** | -15.0% |
| String Obfuscation | 18.3% | 18.9% | -0.7% |
| Tick/Backtick Insertion | 23.2% | 23.3% | -0.2% |

**Phát hiện quan trọng:** Hai yếu tố quyết định nhất cho việc "bắt hay lọt" là:
1. **Reflective Loading** (chênh lệch +51.9%): Mã độc nào gọi `[Reflection.Assembly]::Load`, `Add-Type` với DllImport, hoặc `GetProcAddress` thì mô hình bắt rất tốt.
2. **Hex/Byte Array** (chênh lệch +33.8%): Mã độc có nhúng mảng byte hex (`0x4D, 0x5A...`) tạo ra entropy cao và kích hoạt detector shellcode.

Ngược lại, các kỹ thuật như String Obfuscation và Tick Insertion **KHÔNG giúp phân biệt** (chênh lệch ~0%) — mô hình không hề được huấn luyện để nhận biết chúng.

#### 5.7.3. Case Study — Các file bị bỏ lọt điển hình

**Case 1: `Empire-PowerShell_DomainPasswordSpray.ps1`** (Empire, 17.9 KB)
- **RF confidence:** 0.0286 (rất thấp — mô hình rất tự tin đây là benign)
- **FastText confidence:** 0.0067
- **Kỹ thuật phát hiện:** Tick Insertion (5), Reconnaissance (5), Credential Theft (1)
- **Kỹ thuật VẮNG MẶT:** Base64, Hex Shellcode, Reflective Loading, Process Injection
- **Lý do bị lọt:** Script này là một module chuyên nghiệp với `function`, `param()`, `<#.SYNOPSIS#>`. Nó thực hiện tấn công Password Spray nhưng bằng cách gọi các cmdlet Active Directory chuẩn — hoàn toàn không có shellcode hay encoding.

**Case 2: `Nishang_Add-ConstrainedDelegationBackdoor.ps1`** (Nishang, 4.9 KB)
- **RF confidence:** 0.1857
- **Kỹ thuật phát hiện:** Credential Theft (9), Reconnaissance (2)
- **Kỹ thuật VẮNG MẶT:** 10/12 kỹ thuật không có (bao gồm Base64, Hex, IEX, Reflective Loading)
- **Lý do bị lọt:** Script sử dụng module `ActiveDirectory` chuẩn để cài backdoor qua Constrained Delegation. Mã độc hoàn toàn được viết bằng các cmdlet PowerShell hợp pháp (`Set-ADComputer`, `Set-ADUser`).

**Case 3: `Empire-PowerShell_Invoke-PsExec.ps1`** (Empire, 16.5 KB) — **Gần bị bắt nhất!**
- **RF confidence:** 0.4952 (chỉ thiếu 0.0048 nữa là vượt ngưỡng 0.5)
- **Kỹ thuật phát hiện:** Dynamic Execution (15 matches), Reflective Loading (9 matches)
- **Lý do suýt bắt được:** File này có nhiều lời gọi `System.Reflection` và `.Invoke()`, nhưng thiếu shellcode hex và Base64 — nên tổng điểm chưa đủ vượt ngưỡng.

**Case 4 (Đối chiếu): `PowerSploit_Invoke-TokenManipulation.ps1`** — **BẮT ĐƯỢC** (TP)
- **RF confidence:** 0.9000 (rất cao)
- **Kỹ thuật phát hiện:** IEX (56), Persistence (16), Process Injection (14), Reflective Loading (13), Hex Shellcode (3)
- **Lý do bắt được:** File này chứa đầy đủ các dấu hiệu mà mô hình đã học: API injection (`VirtualAlloc`, `CreateThread`), Reflective Loading, và cả Hex byte patterns.

### 5.8. Thí nghiệm Obfuscation — Kiểm chứng giả thuyết

Để kiểm chứng giả thuyết "mô hình chỉ học dấu hiệu bề mặt", nhóm đã thiết kế thí nghiệm áp dụng **5 kỹ thuật obfuscation** lên cả mã độc mới và file benign, sau đó đánh giá lại bằng mô hình 78 chiều.

#### 5.8.1. Các kỹ thuật obfuscation được áp dụng

| # | Kỹ thuật | Mô tả | Ảnh hưởng đến đặc trưng |
|---|----------|-------|------------------------|
| 1 | **Base64 Wrapping** | Bọc toàn bộ script trong `FromBase64String()` + `IEX` | Tạo chuỗi Base64 dài, tăng Entropy |
| 2 | **Tick Insertion** | Chèn backtick vào từ khóa: `Inv`oke-Exp`ression` | Thay đổi token, phá vỡ pattern matching |
| 3 | **String Reversal** | Đảo ngược script → ghép lại bằng `-join` + `IEX` | Tạo chuỗi rác, thay đổi entropy |
| 4 | **Variable Renaming** | Đổi tên biến thành chuỗi ngẫu nhiên 8 ký tự | Thay đổi FastText embedding |
| 5 | **XOR Encoding** | Mã hóa XOR → tạo mảng hex `0x` → giải mã + `IEX` | Tạo mảng hex giống shellcode |

#### 5.8.2. Kết quả Thí nghiệm A: Obfuscate mã độc mới → Test lại

| Kỹ thuật Obfuscation | Recall (Malicious) | Δ vs Baseline | Giải thích |
|----------------------|:------------------:|:-------------:|-----------|
| **Original (Baseline)** | **26.5%** | — | Mã độc "sạch", mô hình bỏ lọt 73.5% |
| Base64 Wrapping | 1.2% | **-25.4%** ↓ | Script bị thay thế bằng 3 dòng wrapper, mất hết đặc trưng gốc |
| Tick Insertion | 15.4% | **-11.2%** ↓ | Backtick phá vỡ pattern matching của token, giảm điểm |
| String Reversal | 3.1% | **-23.4%** ↓ | Script bị đảo ngược thành chuỗi rác, FastText không hiểu |
| Variable Renaming | 21.3% | **-5.3%** ↓ | Đổi tên biến ít ảnh hưởng vì mô hình không phụ thuộc nhiều vào tên biến |
| **XOR Encoding** | **99.6%** | **+73.1%** ↑↑↑ | Tạo mảng hex `0x` giống shellcode MPSD → mô hình bắt gần như 100% |

**Phát hiện bất ngờ:** Giả thuyết ban đầu cho rằng obfuscation sẽ tăng Recall cho tất cả kỹ thuật. Thực tế, chỉ có **XOR Encoding** (tạo mảng hex) làm Recall tăng vọt lên 99.6%. Các kỹ thuật khác (Base64 Wrapping, String Reversal) lại làm Recall **GIẢM** vì chúng phá hủy các đặc trưng gốc mà mô hình cần để phân loại.

→ **Kết luận:** Mô hình không học "obfuscation nói chung" mà học **một pattern cụ thể**: mảng hex `0x` (đặc trưng Hex/Byte Array Shellcode). Khi obfuscation tạo ra pattern này (XOR Encoding), mô hình bắt 99.6%. Khi obfuscation KHÔNG tạo pattern này, mô hình thậm chí còn bắt TỆ HƠN vì mất luôn các đặc trưng gốc.

#### 5.8.3. Kết quả Thí nghiệm B: Obfuscate file benign → Test lại

| Kỹ thuật Obfuscation | FP Rate (Benign) | Δ vs Baseline | Giải thích |
|----------------------|:----------------:|:-------------:|-----------|
| **Original (Baseline)** | **0.1%** | — | Mô hình gần như không bắt nhầm file sạch |
| Base64 Wrapping | 0.3% | +0.1% | Wrapper Base64 đơn giản, không đủ kích hoạt detector |
| Tick Insertion | 0.1% | +0.0% | Backtick không thay đổi bản chất file sạch |
| String Reversal | **12.4%** | **+12.2%** ↑ | Chuỗi đảo ngược tạo entropy bất thường, 88/712 file bị bắt nhầm |
| Variable Renaming | 0.6% | +0.4% | Tên biến ngẫu nhiên ít ảnh hưởng |
| **XOR Encoding** | **99.9%** | **+99.7%** ↑↑↑ | 711/712 file sạch bị bắt nhầm thành mã độc! |

**Phát hiện cực kỳ quan trọng:** Khi áp dụng XOR Encoding lên file benign (hoàn toàn vô hại), mô hình bắt nhầm **99.9% file sạch** thành mã độc. Điều này chứng minh một cách không thể phản bác rằng:

> **Mô hình M-FastText-2 phát hiện mã độc chủ yếu dựa trên sự hiện diện của mảng hex bytes (`0x...`), KHÔNG PHẢI dựa trên ngữ nghĩa hay ý đồ thực sự của code.** Bất kỳ file nào — dù sạch hay độc — miễn có mảng hex thì mô hình sẽ đánh dấu là malicious.

#### 5.8.4. Bảng tổng hợp thí nghiệm Obfuscation

| Kỹ thuật | Mal Recall | Ben FP Rate | Recall Δ | FP Δ |
|----------|:----------:|:-----------:|:--------:|:----:|
| Original | 26.5% | 0.1% | — | — |
| Base64 Wrapping | 1.2% | 0.3% | -25.4% | +0.1% |
| Tick Insertion | 15.4% | 0.1% | -11.2% | +0.0% |
| String Reversal | 3.1% | 12.4% | -23.4% | +12.2% |
| Variable Renaming | 21.3% | 0.6% | -5.3% | +0.4% |
| **XOR Encoding** | **99.6%** | **99.9%** | **+73.1%** | **+99.7%** |

### 5.9. Thí nghiệm Retrain — Chứng minh kiến trúc không bị lỗi

Để trả lời câu hỏi "Kiến trúc mô hình có vấn đề không, hay chỉ là dữ liệu huấn luyện không phù hợp?", nhóm đã thực hiện 3 thí nghiệm retrain:

| Thí nghiệm | Mô tả | Accuracy | Precision | Recall | F1-Score |
|-------------|-------|:--------:|:---------:|:------:|:--------:|
| **Baseline** | Train MPSD → Test New | 77.69% | 98.80% | 26.54% | 41.84% |
| **EXP1** | 5-Fold CV trên tập mới | **95.40%** | 91.00% | **94.15%** | **92.47%** |
| **EXP2** | 5-Fold CV trên tập gộp (MPSD + New) | **98.05%** | 98.43% | **97.43%** | **97.93%** |
| **EXP3** | Train tập gộp → Test tập mới | **100%** | 100% | **100%** | **100%** |

**Phân tích:**

- **EXP1 (CV trên tập mới):** Kiến trúc 78 chiều đạt 95.40% Accuracy và 94.15% Recall khi được huấn luyện đúng loại dữ liệu. Điều này chứng minh **kiến trúc mô hình hoàn toàn không có vấn đề**.

- **EXP2 (CV trên tập gộp):** Đạt 98.05% Accuracy — gần bằng kết quả trên tập gốc (98.81%). Mô hình có thể học song song cả hai "phong cách" mã độc (obfuscated MPSD + clean pentesting tools) mà không bị xung đột.

- **EXP3 (Train gộp → Test mới):** Đạt 100% trên tập mới. Mặc dù có yếu tố data leakage (tập test nằm trong tập train), thí nghiệm này chứng minh tính khả thi của cơ chế **Continuous Learning** — khi xuất hiện mẫu mã độc mới, chỉ cần bổ sung vào tập train và retrain là mô hình sẽ cập nhật kiến thức ngay lập tức.

## 6. Đề Xuất Cải Thiện

Dựa trên toàn bộ phân tích chuyên sâu, nhóm đề xuất các hướng cải thiện:

1. **Mở rộng tập huấn luyện (Continuous Learning):** Thí nghiệm retrain đã chứng minh: chỉ cần bổ sung mã độc từ pentesting tools vào tập train, Recall tăng từ 26.5% lên 97.43% mà không ảnh hưởng đến khả năng bắt mã độc cũ. Đây là giải pháp thực tiễn và hiệu quả nhất.

2. **Thêm đặc trưng hành vi (behavioral features):** Thí nghiệm obfuscation cho thấy mô hình phụ thuộc quá nhiều vào mảng hex bytes. Cần bổ sung các đặc trưng hành vi cấp cao hơn: có load DLL hay không, có truy cập registry nguy hiểm hay không, có tạo scheduled task không — để phát hiện mã độc Living-off-the-Land.

3. **Cải tiến FastText embedding:** FastText hiện tại chỉ được train trên corpus MPSD (confidence chỉ 2.6% cho mã độc mới). Cần retrain FastText trên corpus đa dạng hơn hoặc sử dụng pre-trained embedding (CodeBERT, SecBERT) đã học ngữ nghĩa rộng.

4. **Multi-view ensemble:** Kết hợp nhiều "góc nhìn" — static features + dynamic behavior + code semantics — thay vì chỉ dựa vào một bộ đặc trưng tĩnh duy nhất. Điều này giúp mô hình bền vững hơn trước cả obfuscation lẫn mã độc "sạch".

## 7. Kết Luận

- Mô hình M-FastText-2 **hoạt động xuất sắc** trên dữ liệu cùng phân phối (Accuracy >98% trên tập gốc MPSD).
- Khi áp dụng lên **dữ liệu mới từ nguồn khác**, hiệu suất giảm đáng kể (Accuracy ~77%, Recall ~26%) do **hiện tượng Domain Shift** giữa "mã độc dropper truyền thống" (MPSD) và "công cụ pentesting chuyên nghiệp" (New Dataset).
- **Phân tích kỹ thuật mã độc** cho thấy: MPSD thiên về kỹ thuật Delivery (shellcode, download payload, process injection), trong khi New Dataset thiên về Post-Exploitation (credential theft, reconnaissance, persistence). Hai "trường phái" tấn công này tạo ra hồ sơ đặc trưng (feature profile) hoàn toàn khác biệt.
- **Phân tích case bị fail** xác định rõ: yếu tố quyết định nhất là Reflective Loading (+51.9% chênh lệch giữa TP và FN) và Hex Shellcode (+33.8%). Mã độc "sạch" không chứa hai yếu tố này gần như chắc chắn bị bỏ lọt.
- **Thí nghiệm Obfuscation** chứng minh mạnh mẽ: mô hình thực chất phát hiện "mảng hex bytes" chứ không hiểu bản chất mã độc. XOR Encoding tạo mảng hex → Recall tăng từ 26.5% lên 99.6%, nhưng đồng thời cũng bắt nhầm 99.9% file benign.
- **Thí nghiệm Retrain** khẳng định kiến trúc 78 chiều **không hề bị lỗi**: khi train trên tập gộp (MPSD + New), Accuracy đạt 98.05% và Recall đạt 97.43%. Đây là minh chứng cho tính linh hoạt và khả năng mở rộng của kiến trúc M-FastText-2.

