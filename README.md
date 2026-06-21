# NT230-G11: Malicious PowerShell Script Detection (M-FastText-2)

Repository này chứa mã nguồn, tập dữ liệu và báo cáo thực nghiệm cho đồ án môn học Cơ chế mã độc (NT230) - Nhóm 11. Đồ án triển khai lại và mở rộng mô hình **M-FastText-2** từ bài báo khoa học về phát hiện mã độc PowerShell dựa trên đặc trưng lai (Hybrid Features).

## Nội dung đồ án

Đồ án được chia thành 3 phần chính và những cải tiến cốt lõi:
- **Phần A:** Nghiên cứu và phân tích tập dữ liệu MPSD (Malicious PowerShell Script Dataset).
- **Phần B:** Hiện thực lại mô hình M-FastText-2 chuẩn theo bài báo gốc. Nhóm đã xây dựng **kiến trúc 78 chiều** tuân thủ tuyệt đối cấu trúc nén đặc trưng (nén 200 hàm thành 1 điểm số, ép FastText xuống 2 chiều) theo bài báo gốc của Fang et al. (2021) nhằm đảm bảo khả năng tổng quát hóa.
- **Phần C & Đóng Góp Mới:** 
  - Thu thập tập dữ liệu mã độc/an toàn hoàn toàn mới từ GitHub (PowerSploit, Nishang, Empire...) và phát hiện hiện tượng "Domain Shift" (Sự suy giảm hiệu năng do lệch phân phối).
  - Đề xuất và triển khai giải pháp **Data Augmentation & Continuous Learning** (Trộn mã độc hiện đại vào tập huấn luyện), giúp mô hình phục hồi xuất sắc độ nhạy (Recall) từ 26.54% lên **97.43%**.

## Cấu trúc thư mục

```text
NT230-G11/
├── src/core/m_fasttext2_model_78dim.py    # Kiến trúc 78 chiều (Chuẩn xác theo bài báo gốc)
├── src/core/m_fasttext2_model_enhanced.py # Kiến trúc cải tiến (Tích hợp Win32 API Features)
├── src/data_prep/collect_new_dataset.py   # Script thu thập dữ liệu mới từ GitHub (Phần C)
├── src/experiments/evaluate_new_dataset_78dim.py # Đánh giá bản 78 chiều trên tập dữ liệu mới
├── src/experiments/evaluate_enhanced_model.py    # Đánh giá mô hình đã được cải tiến
├── src/experiments/retrain_new_dataset.py        # Thí nghiệm Retrain (Giải quyết Domain Shift)
├── requirements.txt                       # Danh sách thư viện Python cần thiết
├── data/mpsd/                             # Tập dữ liệu gốc (Phần A)
├── data/new_dataset/                      # Tập dữ liệu mới thu thập (Phần C)
└── results/                               # Chứa biểu đồ, log chạy chia theo 78dim/ và enhanced/
```

> **Lưu ý:** Thư mục `results/` chứa biểu đồ xuất ra, các file model weights (`.model`, `.npy`, `.pkl`) đã được đưa vào `.gitignore` do kích thước quá lớn (> 2.5GB). Bạn cần tự chạy code để sinh ra model cục bộ.

## Hướng dẫn cài đặt và chạy

### 1. Cài đặt môi trường
Yêu cầu Python 3.8 trở lên. Cài đặt các thư viện cần thiết:
```bash
pip install -r requirements.txt
```

*(Lưu ý: Bạn nên thêm thư mục project vào danh sách loại trừ (Exclusion) của Windows Defender hoặc Antivirus để tránh việc các script PowerShell mã độc trong thư mục data bị xóa mất trong quá trình quét).*

### 2. Chạy Phần B (Huấn luyện và đánh giá trên tập gốc)

Chạy file chính để huấn luyện mô hình M-FastText-2 trên tập dữ liệu MPSD, xuất biểu đồ, và tự động lưu model weights:
```bash
python src/core/m_fasttext2_model_78dim.py
```

### 3. Chạy Phần C & Cải tiến (Kiểm thử trên dữ liệu mới)

**Bước 1: Thu thập dữ liệu**
Chạy script để tự động clone các repository chứa mã độc và mã an toàn từ GitHub về thư mục `data/new_dataset/`:
```bash
python src/data_prep/collect_new_dataset.py
```

**Bước 2: Đánh giá Domain Shift**
Load mô hình đã lưu từ Phần B và dự đoán trên tập dữ liệu vừa thu thập để quan sát sự suy giảm của Recall (Domain Shift):
```bash
python src/experiments/evaluate_new_dataset_78dim.py
```

**Bước 3: Chạy giải pháp Cải tiến (Continuous Learning)**
Kiểm chứng giải pháp Data Augmentation để phục hồi sức mạnh mô hình, đồng thời đánh giá trên mô hình Hybrid (Tích hợp Rule-based kiểm tra API):
```bash
python src/experiments/evaluate_enhanced_model.py
```
