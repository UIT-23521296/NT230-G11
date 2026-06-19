# Mô Tả Chi Tiết Hệ Thống Phát Hiện Mã Độc PowerShell M-FastText-2

## 1. Tổng Quan Hệ Thống

Hệ thống M-FastText-2 là một mô hình học máy phát hiện mã độc PowerShell dựa trên **đặc trưng lai (Hybrid Features)**, kết hợp giữa đặc trưng trích xuất thủ công (Manual Features) và đặc trưng nhúng tự động (FastText Embedding). Mô hình được xây dựng theo bài báo *"Effective method for detecting malicious PowerShell scripts based on hybrid features"* của Fang et al., xuất bản trên tạp chí Neurocomputing năm 2021.

### Kiến trúc tổng quát

```
PowerShell Script (.ps1)
        │
        ├──────────────────────────────────────────┐
        │                                          │
        ▼                                          ▼
  [Manual Feature Extraction]               [FastText Embedding]
        │                                          │
        ├── Textual Features (13 dim)              │
        ├── Function/Token Features (34 dim)       │
        └── AST Node Features (29 dim)             │
        │                                          │
        │    76 dim                           2 dim (Label, Conf)
        │                                          │
        └──────────────┬───────────────────────────┘
                       │
                       ▼
              [Concatenation]
            78-dim Hybrid Vector
                       │
                       ▼
             [Random Forest Classifier]
                       │
                       ▼
              Benign / Malicious
```

---

## 2. Tập Dữ Liệu

### 2.1. Nguồn dữ liệu

Tập dữ liệu MPSD (Malicious PowerShell Script Dataset) được cung cấp bởi bài báo gốc, gồm 3 thư mục con:

| Tập con | Số lượng | Mô tả |
|---------|----------|-------|
| `malicious_pure` | 4,202 | Script mã độc thuần túy, thu thập từ các cơ sở dữ liệu malware và sandbox |
| `mixed_malicious` | 4,202 | Script mã độc đã được trộn (embed) vào trong script an toàn, mô phỏng kỹ thuật fileless malware |
| `powershell_benign_dataset` | 4,316 | Script PowerShell an toàn, thu thập từ PowerShell Gallery và các nguồn hợp pháp |

### 2.2. Gán nhãn

- **Nhãn 1 (Malicious)**: Tất cả script trong `malicious_pure` hoặc `mixed_malicious`
- **Nhãn 0 (Benign)**: Tất cả script trong `powershell_benign_dataset`

### 2.3. Hai thí nghiệm

Hệ thống thực hiện 2 thí nghiệm song song:

- **Experiment 1 (Original)**: `malicious_pure` (4,202) vs `benign` (4,316) = 8,518 mẫu
- **Experiment 2 (Mixed)**: `mixed_malicious` (4,202) vs `benign` (4,316) = 8,518 mẫu

Mục đích: So sánh khả năng phát hiện mã độc "thô" (dễ) vs mã độc đã trộn lẫn (khó).

---

## 3. Trích Xuất Đặc Trưng Thủ Công (Manual Features) — 76 chiều

### 3.1. Đặc Trưng Văn Bản (Textual Features) — 13 chiều

Đặc trưng văn bản phân tích các thuộc tính bề mặt của script, bao gồm:

#### Feature 1: Sự tồn tại của Shellcode (1 chiều, nhị phân 0/1)

Hệ thống quét script tìm các dấu hiệu shellcode thông qua 4 pattern regex:
- **Hex byte arrays**: `0x4D, 0x5A, 0x90` — dãy byte dạng hexadecimal, thường xuất hiện trong payload mã độc
- **C-style hex escapes**: `\x4D\x5A` — ký tự escape dạng hex
- **PowerShell byte array cast**: `[Byte[]]` — ép kiểu mảng byte, dùng để chứa shellcode trong bộ nhớ
- **Long Base64 strings**: Chuỗi Base64 dài > 48 ký tự — kỹ thuật mã hóa phổ biến để che giấu payload

Nếu phát hiện bất kỳ pattern nào → trả về 1, ngược lại trả về 0.

#### Feature 2: Information Entropy (1 chiều, số thực)

Tính **Shannon Entropy** của toàn bộ nội dung script:

$$H(X) = -\sum_{i=1}^{n} p(x_i) \log_2 p(x_i)$$

Trong đó $p(x_i)$ là tần suất xuất hiện của ký tự $x_i$ trong script.

**Ý nghĩa**: Trái ngược với file nhị phân (.exe) bị pack sẽ có entropy cao, trong môi trường văn bản như PowerShell, mã độc bị obfuscate (ví dụ: dùng mảng Hex `0xfc, 0xe8...`) thường có tập ký tự bị thu hẹp đáng kể (chỉ dùng `0-9`, `a-f`, `x`, `,`). Sự lặp lại liên tục của một tập ký tự giới hạn này làm cho độ hỗn loạn giảm xuống, dẫn đến entropy **THẤP HƠN**. Ngược lại, kịch bản lành tính (Benign) sử dụng ngôn ngữ tự nhiên với từ vựng phong phú, đa dạng ký tự nên có mức phân bổ đồng đều hơn, tạo ra entropy **CAO HƠN**. Đây là một phát hiện quan trọng được xác nhận trong bài báo.

#### Features 3-7: Top 5 ký tự xuất hiện nhiều nhất (5 chiều, số nguyên)

Đếm tần suất của mọi ký tự trong script, chọn ra 5 ký tự xuất hiện nhiều nhất, và chuyển đổi chúng sang **mã ASCII**. Ví dụ: nếu ký tự xuất hiện nhiều nhất là dấu cách (space) → giá trị = 32.

**Ý nghĩa**: Mã độc obfuscate thường có phân bố ký tự khác biệt — ví dụ ký tự `+`, `/`, `=` xuất hiện nhiều (đặc trưng của Base64), trong khi script bình thường thường có dấu cách, chữ cái, dấu `-` chiếm ưu thế.

#### Features 8-10: Đặc trưng chuỗi (3 chiều)

Trích xuất tất cả các chuỗi ký tự (string literals) trong ngoặc kép `"..."` và ngoặc đơn `'...'`:
- **Số lượng chuỗi**: Tổng số string literals trong script
- **Chiều dài tối đa**: Chuỗi dài nhất (mã độc thường có chuỗi Base64 rất dài)
- **Chiều dài trung bình**: Trung bình chiều dài các chuỗi

#### Feature 11: Sự tồn tại của URL hoặc IP (1 chiều, nhị phân 0/1)

Quét script tìm:
- **URL**: Pattern `http://` hoặc `https://` theo sau bởi domain
- **Địa chỉ IP**: Pattern `xxx.xxx.xxx.xxx`

**Ý nghĩa**: Nhiều mã độc PowerShell tải payload từ server C2 (Command & Control) thông qua `Invoke-WebRequest` hoặc `DownloadString`. Sự xuất hiện của URL/IP là dấu hiệu quan trọng.

#### Features 12-13: Biến số (Variables) (2 chiều, số nguyên)

Đếm các đặc điểm về biến trong script:
- **Tổng số biến**: Đếm tổng số lượng biến được định nghĩa hoặc gọi trong script.
- **Biến đặc thù**: Đếm số lần xuất hiện của các biến PowerShell có tên đáng ngờ (ví dụ: `$cmd`, `$shell`, `$exec`, `$download`, `$payload`, `$shellcode`...).

---

**Tổng cộng: 1 + 33 = 34 features**

---

### 3.3. Đặc Trưng Nút AST (AST Node Features) — 29 chiều

AST (Abstract Syntax Tree) là cây cú pháp trừu tượng đại diện cho cấu trúc logic của script. Hệ thống trích xuất tần suất xuất hiện của các loại nút AST.

#### 23 nút AST chính (theo Figure 4 bài báo)

Hệ thống đếm tần suất xuất hiện của 23 loại cấu trúc cú pháp PowerShell:

**Nhóm câu lệnh (Statement-level)**:
| Nút AST | Pattern nhận diện | Ý nghĩa |
|---------|-------------------|---------|
| ScriptBlockAst | `{` | Khối script (mở ngoặc nhọn) |
| NamedBlockAst | `begin{`, `process{`, `end{` | Các khối đặt tên trong pipeline |
| StatementBlockAst | `if{`, `for{`, `try{`, ... | Khối câu lệnh điều kiện/vòng lặp |
| PipelineAst | `\|` | Pipeline (ống dẫn dữ liệu) |
| AssignmentStatementAst | `$var =` | Câu lệnh gán giá trị |
| IfStatementAst | `if (` | Câu lệnh điều kiện if |
| ForEachStatementAst | `foreach (` | Vòng lặp foreach |
| WhileStatementAst | `while (` | Vòng lặp while |
| ForStatementAst | `for (` | Vòng lặp for |
| DoWhileStatementAst | `do {` | Vòng lặp do-while |
| SwitchStatementAst | `switch` | Câu lệnh switch |
| TryStatementAst | `try {` | Khối try-catch |
| ReturnStatementAst | `return` | Trả về giá trị |
| ThrowStatementAst | `throw` | Ném ngoại lệ |
| ExitStatementAst | `exit` | Thoát script |
| BreakStatementAst | `break` | Ngắt vòng lặp |
| ContinueStatementAst | `continue` | Tiếp tục vòng lặp |
| FunctionDefinitionAst | `function Name` | Định nghĩa hàm |

**Nhóm biểu thức (Expression-level)**:
| Nút AST | Pattern nhận diện | Ý nghĩa |
|---------|-------------------|---------|
| CommandAst | `Verb-Noun` | Lời gọi cmdlet |
| CommandParameterAst | `-ParamName` | Tham số cmdlet |
| VariableExpressionAst | `$variableName` | Biểu thức biến |
| MemberExpressionAst | `.member` (không gọi) | Truy cập thuộc tính |
| InvokeMemberExpressionAst | `.method()` | Gọi phương thức |

#### 5 nút AST đặc biệt (đặc trưng mã độc)

| Nút AST | Pattern | Tại sao liên quan mã độc |
|---------|---------|--------------------------|
| TypeExpressionAst | `[TypeName]` | Ép kiểu, mã độc dùng `[System.Convert]`, `[System.Net.WebClient]` |
| ConvertExpressionAst | `[Type]$var` | Chuyển đổi kiểu biến, dùng trong decode payload |
| ScriptBlockExpressionAst | `$var = {` hoặc `{param(` | Script block ẩn danh, dùng để thực thi code động |
| SubExpressionAst | `$(...)` | Biểu thức con, dùng để xây dựng lệnh động |
| IndexExpressionAst | `$var[i]` | Truy cập phần tử, dùng trong xử lý byte array |

#### 1 feature: AST Depth (Độ sâu lồng)

Tính **độ sâu lồng tối đa** của script bằng cách theo dõi các cặp ngoặc nhọn `{}`, bỏ qua ngoặc nhọn nằm trong chuỗi ký tự.

**Ý nghĩa**: Mã độc obfuscate thường có cấu trúc lồng rất sâu (nhiều lớp decode/decompress), trong khi script bình thường thường phẳng hơn.

**Tổng AST: 23 + 5 + 1 = 29 features**

---

## 4. Nhúng Ngữ Nghĩa FastText (FastText Embedding) — 300 chiều

### 4.1. Giới thiệu FastText

FastText là mô hình nhúng từ (word embedding) được phát triển bởi Facebook AI Research. Điểm khác biệt quan trọng so với Word2Vec là FastText sử dụng **character n-grams** (chuỗi ký tự con) để biểu diễn từ, cho phép xử lý được các từ chưa từng thấy (out-of-vocabulary) — rất hữu ích khi phân tích mã nguồn có nhiều tên biến, tên hàm sáng tạo.

### 4.2. Tiền xử lý — Tokenization

Mỗi script PowerShell được tokenize (tách từ) như sau:
1. **Loại bỏ comment**: Xóa comment một dòng (`# ...`) và comment nhiều dòng (`<# ... #>`)
2. **Tách token**: Sử dụng regex trích xuất các từ, biến (`$var`), và toán tử
3. **Chuẩn hóa**: Chuyển tất cả token về lowercase

Kết quả: Mỗi script trở thành một "câu" (danh sách các token).

### 4.3. Huấn luyện mô hình FastText

Mô hình FastText được huấn luyện trên **toàn bộ corpus** (tất cả scripts trong dataset) với các tham số:

| Tham số | Giá trị | Ý nghĩa |
|---------|---------|---------|
| `vector_size` | 300 | Mỗi từ được biểu diễn bằng vector 300 chiều |
| `sg` | 1 (skip-gram) | Mô hình skip-gram: dự đoán ngữ cảnh từ từ trung tâm |
| `min_n` | 2 | Character n-gram tối thiểu = 2 ký tự |
| `max_n` | 2 | Character n-gram tối đa = 2 ký tự |
| `window` | 5 | Cửa sổ ngữ cảnh: xét 5 từ trước và sau |
| `min_count` | 1 | Giữ lại tất cả các từ (kể cả xuất hiện 1 lần) |
| `epochs` | 10 | Huấn luyện 10 vòng (epoch) qua toàn bộ corpus |

**Lý do chọn 2-grams**: Tên mô hình "M-FastText-**2**" lấy từ tham số n=2. Bài báo đã thí nghiệm với n=1, 2, 3 và nhận thấy n=2 cho kết quả tốt nhất trên tập Mixed (Accuracy 97.76%).

### 4.4. Tạo embedding cho mỗi script

Sau khi huấn luyện, mỗi script được chuyển thành vector 300 chiều bằng cách:
1. Tokenize script thành danh sách token
2. Tra cứu vector 300 chiều cho mỗi token từ mô hình FastText
3. Tính **trung bình cộng (average)** của tất cả vector token → vector 300 chiều đại diện cho cả script

$$\vec{v}_{script} = \frac{1}{N} \sum_{i=1}^{N} \vec{v}_{token_i}$$

**Ý nghĩa**: Vector embedding mang thông tin **ngữ nghĩa** của script — các script có nội dung tương tự sẽ có vector gần nhau trong không gian 300 chiều. Điều này bổ sung cho các đặc trưng thủ công vốn chỉ nắm bắt thông tin bề mặt.

---

## 5. Ghép Nối Đặc Trưng Lai (Feature Concatenation)

Thay vì nối trực tiếp tất cả các nhóm đặc trưng thành một vector khổng lồ (vốn dễ gây ra hiện tượng Overfitting - Học vẹt trên dữ liệu huấn luyện), hệ thống áp dụng **Kiến trúc chuẩn nén thông tin (78 chiều)** nhằm mang lại khả năng tổng quát hóa (Generalization) tối ưu nhất, đặc biệt khi đối mặt với mã độc thay đổi hành vi:

1. **Nén FastText (300D $\rightarrow$ 2D):** Thay vì để mô hình Random Forest bị "ngợp" bởi 300 chiều không gian từ vựng, hệ thống sử dụng một bộ phân loại phụ (Logistic Regression) để ánh xạ 300 chiều này thành 2 giá trị cực kỳ súc tích: Nhãn dự đoán (0 hoặc 1) và Xác suất độ tin cậy (Confidence Score).
2. **Nén Token Features (200D $\rightarrow$ 1D):** Thay vì đếm riêng lẻ tần suất của 200 hàm (khiến mô hình dễ bị ghi nhớ cứng nhắc một vài hàm phổ biến), hệ thống chấm điểm rủi ro cho từng hàm (Hàm an toàn: -1, Hàm nguy hiểm: +1) và cộng dồn lại thành **1 giá trị tổng duy nhất** (Total functions rating - Tổng điểm rủi ro bù trừ). Cơ chế này mô phỏng lại cách phân tích đánh giá của các chuyên gia bảo mật.
3. **Giữ nguyên 33 Member Tokens (33D):** Giữ lại tỷ lệ phân bố của 33 phương thức gọi lệnh thường bị lợi dụng nhất (ví dụ: `.DownloadString`, `.Invoke`) vì đây là các kỹ thuật cốt lõi (Living-off-the-Land) mang tính nền tảng của PowerShell, rất khó để hacker thay đổi mà không làm hỏng script.

```
[FastText (Compressed) | Textual | Function/Token | AST Features]
          2 dim           13 dim         34 dim         29 dim
                               = 78 dim tổng cộng
```
**Ý nghĩa khoa học của thiết kế**: Việc nén và giảm chiều dữ liệu (Dimensionality Reduction) hoạt động như một cơ chế **Điều chuẩn (Regularization)** mạnh mẽ. Nó buộc thuật toán Random Forest phải học cách phân loại dựa trên bản chất tổng quát của script (như tổng điểm rủi ro, cấu trúc cây logic AST) thay vì "học vẹt" (Shortcut Learning) sự xuất hiện của một hàm cụ thể nào đó. Nhờ vậy, khi đối mặt với các công cụ mã độc hoàn toàn mới chưa từng thấy, hệ thống không bị "mù" mà vẫn duy trì được khả năng nhận diện hành vi đáng ngờ.

Các giá trị NaN hoặc Infinity (nếu có) được thay thế bằng 0 trước khi đưa vào bộ phân loại.

---

## 6. Phân Loại Bằng Random Forest

### 6.1. Bộ phân loại Random Forest

Random Forest là thuật toán ensemble learning, kết hợp nhiều cây quyết định (decision trees) để đưa ra dự đoán cuối cùng bằng bỏ phiếu đa số (majority voting).

Tham số được tối ưu trong bài báo:

| Tham số | Giá trị | Ý nghĩa |
|---------|---------|---------|
| `n_estimators` | 70 | Số lượng cây quyết định trong rừng |
| `max_features` | 8 | Số lượng đặc trưng tối đa được xét khi phân nhánh mỗi nút |
| `random_state` | 0 | Hạt giống ngẫu nhiên cố định để tái tạo kết quả |

Bài báo đã thực hiện grid search trên `n_estimators` và `max_features` để tìm ra bộ tham số tối ưu.

### 6.2. Quá trình huấn luyện

Với mỗi cây quyết định trong rừng:
1. **Bootstrap sampling**: Lấy ngẫu nhiên (có hoàn lại) một tập con từ dữ liệu huấn luyện
2. **Feature subspace**: Tại mỗi nút, chỉ xét **8 đặc trưng** ngẫu nhiên (trong 574) để tìm ngưỡng phân chia tốt nhất
3. **Grow tree**: Phát triển cây đến khi các lá đều thuần (pure) hoặc không thể phân chia thêm
4. **Lặp lại** cho 70 cây

### 6.3. Quá trình dự đoán

Khi dự đoán một script mới:
1. Trích xuất vector 78 chiều
2. Đưa vector qua **tất cả 70 cây** → mỗi cây cho một phiếu bầu (Benign hoặc Malicious)
3. Kết quả cuối cùng = **lớp có nhiều phiếu nhất** (majority voting)
4. Xác suất = tỷ lệ cây bầu cho mỗi lớp (dùng cho ROC curve)

---

## 7. Đánh Giá Mô Hình — 5-Fold Stratified Cross-Validation

### 7.1. Phương pháp chia tập

Hệ thống sử dụng **5-Fold Stratified Cross-Validation**:

1. Toàn bộ dataset (8,518 mẫu) được chia thành **5 phần (fold) bằng nhau**
2. **Stratified**: Mỗi fold duy trì tỷ lệ Benign/Malicious giống như tập gốc (~50.7%/49.3%)
3. Lần lượt:
   - Fold 1 làm test, Fold 2-5 làm train
   - Fold 2 làm test, Fold 1,3-5 làm train
   - ... (lặp 5 lần)
4. Mỗi lần: train = ~6,814 mẫu (80%), test = ~1,704 mẫu (20%)

```
Lần 1:  [TEST] [TRAIN] [TRAIN] [TRAIN] [TRAIN]
Lần 2:  [TRAIN] [TEST] [TRAIN] [TRAIN] [TRAIN]
Lần 3:  [TRAIN] [TRAIN] [TEST] [TRAIN] [TRAIN]
Lần 4:  [TRAIN] [TRAIN] [TRAIN] [TEST] [TRAIN]
Lần 5:  [TRAIN] [TRAIN] [TRAIN] [TRAIN] [TEST]
```

**Ưu điểm**: Mọi mẫu đều được dùng để test đúng 1 lần → kết quả đánh giá khách quan, không phụ thuộc vào cách chia ngẫu nhiên.

### 7.2. Các chỉ số đánh giá

Với mỗi fold, hệ thống tính 4 chỉ số:

**Accuracy (Độ chính xác)**:
$$Accuracy = \frac{TP + TN}{TP + TN + FP + FN}$$

**Precision (Độ chính xác dương)**:
$$Precision = \frac{TP}{TP + FP}$$

**Recall (Độ nhạy)**:
$$Recall = \frac{TP}{TP + FN}$$

**F1-Score (Trung bình điều hòa)**:
$$F1 = 2 \times \frac{Precision \times Recall}{Precision + Recall}$$

Trong đó:
- TP (True Positive): Mã độc được phát hiện đúng là mã độc
- TN (True Negative): An toàn được phát hiện đúng là an toàn
- FP (False Positive): An toàn bị phát hiện nhầm là mã độc
- FN (False Negative): Mã độc bị bỏ sót, phát hiện nhầm là an toàn

Kết quả cuối cùng = **trung bình cộng** của 5 fold.

### 7.3. Visualization

Hệ thống tạo ra các biểu đồ trực quan:

- **Confusion Matrix**: Ma trận nhầm lẫn hiển thị số lượng TP, TN, FP, FN
- **ROC Curve**: Đường cong ROC thể hiện trade-off giữa TPR và FPR, kèm AUC (Area Under Curve)
- **Per-Fold Accuracy**: Biểu đồ cột hiển thị accuracy từng fold
- **Performance Comparison**: So sánh hiệu suất Original vs Mixed dataset

---

## 8. Tổng Hợp Quy Trình Thực Thi (Pipeline)

Toàn bộ quy trình được thực thi theo 7 bước tuần tự:

### Bước 1: Nạp dữ liệu
- Đọc toàn bộ file `.ps1` từ 3 thư mục dataset
- Xử lý encoding (UTF-8, Latin-1)
- Lọc bỏ script rỗng

### Bước 2: Khám phá Top Tokens
- Quét tất cả scripts → Top 200 functions
- Quét chỉ malicious scripts → Top 33 member tokens
- Kết quả dùng chung cho cả 2 thí nghiệm

### Bước 3: Huấn luyện FastText
- Tokenize toàn bộ corpus
- Train mô hình FastText skip-gram 300d, 2-grams
- Kết quả: mô hình có thể chuyển bất kỳ token nào thành vector 300 chiều

### Bước 4: Trích xuất đặc trưng lai
- Ghép nối → vector 78 chiều lai
- Thực hiện cho cả 2 tập (Original và Mixed)

### Bước 5: Huấn luyện và đánh giá
- 5-Fold Stratified Cross-Validation
- Trong mỗi fold: train Random Forest (70 trees, 8 max_features) trên 80% dữ liệu, test trên 20%
- Tính Accuracy, Precision, Recall, F1 cho mỗi fold
- Tính trung bình 5 fold

### Bước 6: Trực quan hóa
- Tạo Confusion Matrix, ROC Curve, biểu đồ so sánh
- Lưu vào thư mục `results/`

### Bước 7: Lưu mô hình
- Lưu FastText model (`m_fasttext2.model`) — dùng cho nhúng từ vựng
- Lưu Random Forest classifier (`rf_classifier.pkl`) — dùng cho phân loại
- Lưu Token config (`top_tokens.json`) — dùng cho trích xuất đặc trưng token

---

## 9. Kết Quả Thực Nghiệm

### Experiment 1: Original Dataset (malicious_pure vs benign)

| Fold | Accuracy | Precision | Recall | F1-Score |
|------|----------|-----------|--------|----------|
| 1 | 0.9906 | 0.9940 | 0.9869 | 0.9905 |
| 2 | 0.9847 | 0.9939 | 0.9750 | 0.9844 |
| 3 | 0.9836 | 0.9963 | 0.9702 | 0.9831 |
| 4 | 0.9794 | 0.9903 | 0.9679 | 0.9789 |
| 5 | 0.9888 | 0.9964 | 0.9810 | 0.9886 |
| **AVG** | **0.9854** | **0.9942** | **0.9762** | **0.9851** |

### Experiment 2: Mixed Dataset (mixed_malicious vs benign)

| Fold | Accuracy | Precision | Recall | F1-Score |
|------|----------|-----------|--------|----------|
| 1 | 0.9531 | 0.9798 | 0.9239 | 0.9510 |
| 2 | 0.9583 | 0.9837 | 0.9310 | 0.9566 |
| 3 | 0.9548 | 0.9787 | 0.9286 | 0.9530 |
| 4 | 0.9571 | 0.9800 | 0.9321 | 0.9555 |
| 5 | 0.9554 | 0.9775 | 0.9310 | 0.9537 |
| **AVG** | **0.9557** | **0.9799** | **0.9293** | **0.9540** |

### So sánh với bài báo gốc

| Metric | Bài báo (Original) | Triển khai (Original) | Bài báo (Mixed) | Triển khai (Mixed) |
|--------|--------------------:|----------------------:|----------------:|-----------------:|
| Accuracy (78D)  | 98.93% | 98.54% | 97.76% | 95.57% |

Sai số nằm trong khoảng chấp nhận được (~0.1-2%) cho re-implementation do khác biệt về AST parser, thư viện FastText, và random seed. Đáng chú ý là phiên bản 78 chiều rất sát với kết quả trong bài báo.

---

## 10. Những Cải Tiến & Đóng Góp Mới Của Đồ Án

Mặc dù hệ thống M-FastText-2 hoạt động rất tốt trên tập dữ liệu chuẩn, nhóm đã thực hiện các đánh giá mở rộng và đề xuất những giải pháp cải tiến cốt lõi nhằm nâng cấp hệ thống để đáp ứng được môi trường thực tế hiện nay:

### 10.1. Khám phá Lỗ hổng Domain Shift
Bài báo gốc không tính đến sự thay đổi bản chất của mã độc (Domain Shift). Khi nhóm kiểm thử mô hình trên một tập dữ liệu hoàn toàn mới chứa các công cụ APT/Pentest hiện đại (như PowerSploit, Nishang - viết mã "sạch" theo phong cách Living-off-the-Land), **tỷ lệ nhận diện (Recall) của mô hình đã giảm mạnh từ 97.62% xuống còn 26.54%**.

### 10.2. Thực nghiệm Đa Thuật toán & Bản chất vấn đề
Nhóm đã thay thế thuật toán Random Forest bằng **Mạng Nơ-ron (MLP)** và **Gradient Boosting (GBDT)** để kiểm chứng. Kết quả cho thấy cả MLP và GBDT đều thất bại thảm hại hơn (Recall rớt xuống 5% - 14%). Thực nghiệm này chứng minh nguyên nhân không phải do thuật toán yết kém, mà do mô hình bị mắc kẹt vào hiện tượng **Shortcut Learning (Học vẹt)**: Mạng Nơ-ron đã quá tập trung học các đặc trưng "dễ" (như Shellcode) của tập huấn luyện cũ, và hoàn toàn bỏ qua các đặc trưng hành vi tinh vi.

### 10.3. Giải pháp Data Augmentation & Continuous Learning
Từ phát hiện trên, đồ án đề xuất giải pháp cốt lõi: Không thay đổi thuật toán, mà thay đổi cách huấn luyện. Thông qua quy trình **Làm giàu dữ liệu (Data Augmentation)** và **Học liên tục (Continuous Learning)** — tức là chủ động trộn thêm các mẫu mã độc Pentesting hiện đại vào tập huấn luyện cũ để tái huấn luyện — mô hình đã phục hồi thành công khả năng nhận diện mã độc tàng hình, **đưa Recall từ mức 26.54% lên vượt mốc 97.43%**.