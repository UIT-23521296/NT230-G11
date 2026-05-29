# NT230-G11: Malicious PowerShell Script Detection (M-FastText-2)

Repository này chứa mã nguồn, tập dữ liệu và báo cáo thực nghiệm cho đồ án môn học Cơ chế mã độc (NT230) - Nhóm 11. Đồ án triển khai lại và mở rộng mô hình **M-FastText-2** từ bài báo khoa học về phát hiện mã độc PowerShell dựa trên đặc trưng lai (Hybrid Features).

## Nội dung đồ án

Đồ án được chia thành 3 phần chính:
- **Phần A:** Nghiên cứu và phân tích tập dữ liệu MPSD (Malicious PowerShell Script Dataset).
- **Phần B:** Hiện thực lại mô hình M-FastText-2. Nhóm đã xây dựng **2 phiên bản kiến trúc**:
  - **Phiên bản 574 chiều:** Trực tiếp ghép nối toàn bộ 200 đặc trưng hàm để tối ưu hóa khả năng phát hiện trên tập dữ liệu cũ.
  - **Phiên bản 78 chiều:** Tuân thủ tuyệt đối cấu trúc nén đặc trưng (nén 200 hàm thành 1 điểm số, ép FastText xuống 2 chiều) theo bài báo gốc của Fang et al. (2021).
- **Phần C:** Thu thập tập dữ liệu mã độc/an toàn hoàn toàn mới từ GitHub (PowerSploit, Nishang, Empire...) và phát hiện hiện tượng "Domain Shift" (Sự suy giảm hiệu năng do lệch phân phối), đồng thời chứng minh kiến trúc 78 chiều có tính **tổng quát hóa (Generalization)** tốt hơn.

## Cấu trúc thư mục

```text
NT230-G11/
├── m_fasttext2_model.py          # Kiến trúc 574 chiều (Trích xuất đặc trưng & Train mô hình)
├── m_fasttext2_model_78dim.py    # Kiến trúc 78 chiều (Chuẩn xác theo mô tả bài báo gốc)
├── reproduce_table3.py           # Tái tạo Table 3 so sánh các mô hình
├── collect_new_dataset.py        # Script thu thập dữ liệu mới từ GitHub (Phần C)
├── evaluate_new_dataset.py       # Đánh giá bản 574 chiều trên tập dữ liệu mới
├── evaluate_new_dataset_78dim.py # Đánh giá bản 78 chiều trên tập dữ liệu mới
├── REPORT_PART_C.md              # Báo cáo chi tiết kết quả Phần C
├── requirements.txt              # Danh sách thư viện Python cần thiết
├── mpsd/                         # Tập dữ liệu gốc (Phần A)
├── new_dataset/                  # Tập dữ liệu mới thu thập (Phần C)
└── results/                      # Chứa biểu đồ, log chạy chia theo 574dim/ và 78dim/
```

> **Lưu ý:** Thư mục `results/` chứa biểu đồ xuất ra, các file model weights (`.model`, `.npy`, `.pkl`) đã được đưa vào `.gitignore` do kích thước quá lớn (> 2.5GB). Bạn cần tự chạy code để sinh ra model cục bộ.

## Hướng dẫn cài đặt và chạy

### 1. Cài đặt môi trường
Yêu cầu Python 3.8 trở lên. Cài đặt các thư viện cần thiết:
```bash
pip install -r requirements.txt
```

*(Lưu ý: Bạn nên thêm thư mục project vào danh sách loại trừ (Exclusion) của Windows Defender hoặc Antivirus để tránh việc các script PowerShell mã độc trong `mpsd` bị xóa mất trong quá trình quét).*

### 2. Chạy Phần B (Huấn luyện và đánh giá trên tập gốc)

Chạy các file chính để huấn luyện mô hình M-FastText-2 trên tập dữ liệu MPSD, xuất biểu đồ, và tự động lưu model weights:
```bash
# Chạy bản 574 chiều
python m_fasttext2_model.py

# Chạy bản 78 chiều (Chuẩn bài báo)
python m_fasttext2_model_78dim.py
```

Để tái tạo **Bảng 3 (Table 3)** so sánh 7 biến thể mô hình khác nhau trên tập Mixed:
```bash
python reproduce_table3.py
```

### 3. Chạy Phần C (Kiểm thử trên dữ liệu mới)

**Bước 1: Thu thập dữ liệu**
Chạy script để tự động clone các repository chứa mã độc và mã an toàn từ GitHub về thư mục `new_dataset/`:
```bash
python collect_new_dataset.py
```

**Bước 2: Đánh giá**
Load 2 mô hình đã lưu từ Phần B và dự đoán trên tập dữ liệu vừa thu thập để xem khả năng tổng quát hóa (bản 78 chiều sẽ thể hiện sự vượt trội):
```bash
python evaluate_new_dataset.py
python evaluate_new_dataset_78dim.py
```

Kết quả báo cáo phân tích chi tiết cho phần C có tại file `REPORT_PART_C.md`.
