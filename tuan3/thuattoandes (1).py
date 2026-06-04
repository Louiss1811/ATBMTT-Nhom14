# -*- coding: utf-8 -*-
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from Crypto.Cipher import DES, DES3  # Bổ sung DES3 để hỗ trợ khóa 16/24 bytes
from Crypto.Util.Padding import pad, unpad 
import base64
import string
import secrets 
import os

class DESApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Chương trình Mã hóa & Giải mã DES / 3DES")
        self.geometry("1000x650") # Tăng chiều cao để chứa thêm các tùy chọn
        self.configure(padx=10, pady=10)

        # Cấu hình font chữ
        self.default_font = ("Arial", 10)
        self.bold_font = ("Arial", 10, "bold")

        self.create_widgets()

    def create_widgets(self):
        # Chia làm 2 cột chính
        self.frame_left = tk.LabelFrame(self, text=" 🔒 MÃ HÓA ", font=("Arial", 12, "bold"), fg="blue", padx=10, pady=10)
        self.frame_left.grid(row=0, column=0, sticky="nsew", padx=10)

        self.frame_right = tk.LabelFrame(self, text=" 🔓 GIẢI MÃ ", font=("Arial", 12, "bold"), fg="blue", padx=10, pady=10)
        self.frame_right.grid(row=0, column=1, sticky="nsew", padx=10)

        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        self.setup_encryption_ui()
        self.setup_decryption_ui()

    # ================= KHUNG MÃ HÓA =================
    def setup_encryption_ui(self):
        tk.Label(self.frame_left, text="Văn bản gốc:", font=self.bold_font).grid(row=0, column=0, sticky="w", pady=5)
        self.txt_plain_enc = tk.Text(self.frame_left, height=4, width=40, font=self.default_font)
        self.txt_plain_enc.grid(row=0, column=1, columnspan=2, pady=5)
        
        tk.Button(self.frame_left, text="📂 Tải tệp", bg="#1976D2", fg="white", font=self.bold_font, command=lambda: self.load_file(self.txt_plain_enc)).grid(row=1, column=2, sticky="e", pady=2)

        # Tùy chọn Độ dài Khóa
        tk.Label(self.frame_left, text="Độ dài khóa:", font=self.bold_font).grid(row=2, column=0, sticky="w", pady=5)
        self.cbb_key_len_enc = ttk.Combobox(self.frame_left, values=["8 bytes (DES)", "16 bytes (3DES)", "24 bytes (3DES)"], state="readonly", width=37)
        self.cbb_key_len_enc.current(0)
        self.cbb_key_len_enc.grid(row=2, column=1, columnspan=2, pady=5)

        tk.Label(self.frame_left, text="🔑 Khóa:", font=self.bold_font).grid(row=3, column=0, sticky="w", pady=5)
        self.ent_key_enc = tk.Entry(self.frame_left, font=self.default_font, width=40)
        self.ent_key_enc.grid(row=3, column=1, columnspan=2, pady=5)
        
        btn_frame_enc_key = tk.Frame(self.frame_left)
        btn_frame_enc_key.grid(row=4, column=1, columnspan=2, sticky="e")
        tk.Button(btn_frame_enc_key, text="Sinh khóa", bg="#F57C00", fg="white", font=self.bold_font, width=10, command=self.generate_key).pack(side="left", padx=5)
        tk.Button(btn_frame_enc_key, text="Lưu khóa", bg="#1976D2", fg="white", font=self.bold_font, width=10, command=lambda: self.save_file(self.ent_key_enc.get())).pack(side="left")

        # Tùy chọn Định dạng đầu ra
        tk.Label(self.frame_left, text="Định dạng đầu ra:", font=self.bold_font).grid(row=5, column=0, sticky="w", pady=5)
        self.cbb_format_enc = ttk.Combobox(self.frame_left, values=["Base64", "Hex"], state="readonly", width=37)
        self.cbb_format_enc.current(0)
        self.cbb_format_enc.grid(row=5, column=1, columnspan=2, pady=5)

        tk.Label(self.frame_left, text="Văn bản Mã Hóa:", font=self.bold_font).grid(row=6, column=0, sticky="w", pady=5)
        self.txt_cipher_enc = tk.Text(self.frame_left, height=4, width=40, font=self.default_font)
        self.txt_cipher_enc.grid(row=6, column=1, columnspan=2, pady=5)

        action_frame_enc = tk.Frame(self.frame_left)
        action_frame_enc.grid(row=7, column=0, columnspan=3, pady=15)
        tk.Button(action_frame_enc, text="🔒 Mã Hóa", bg="#388E3C", fg="white", font=self.bold_font, width=12, command=self.encrypt_action).pack(side="left", padx=10)
        tk.Button(action_frame_enc, text="Xóa dữ liệu", bg="#D32F2F", fg="white", font=self.bold_font, width=12, command=lambda: self.clear_all("enc")).pack(side="left", padx=10)
        tk.Button(action_frame_enc, text="💾 Lưu kết quả", bg="#1976D2", fg="white", font=self.bold_font, width=12, command=lambda: self.save_file(self.txt_cipher_enc.get("1.0", tk.END))).pack(side="left", padx=10)

    # ================= KHUNG GIẢI MÃ =================
    def setup_decryption_ui(self):
        tk.Label(self.frame_right, text="Văn bản mã hóa:", font=self.bold_font).grid(row=0, column=0, sticky="w", pady=5)
        self.txt_cipher_dec = tk.Text(self.frame_right, height=4, width=40, font=self.default_font)
        self.txt_cipher_dec.grid(row=0, column=1, columnspan=2, pady=5)
        
        tk.Button(self.frame_right, text="📂 Tải tệp", bg="#1976D2", fg="white", font=self.bold_font, command=lambda: self.load_file(self.txt_cipher_dec)).grid(row=1, column=2, sticky="e", pady=2)

        # Tùy chọn Độ dài Khóa
        tk.Label(self.frame_right, text="Độ dài khóa:", font=self.bold_font).grid(row=2, column=0, sticky="w", pady=5)
        self.cbb_key_len_dec = ttk.Combobox(self.frame_right, values=["8 bytes (DES)", "16 bytes (3DES)", "24 bytes (3DES)"], state="readonly", width=37)
        self.cbb_key_len_dec.current(0)
        self.cbb_key_len_dec.grid(row=2, column=1, columnspan=2, pady=5)

        tk.Label(self.frame_right, text="🔑 Khóa:", font=self.bold_font).grid(row=3, column=0, sticky="w", pady=5)
        self.ent_key_dec = tk.Entry(self.frame_right, font=self.default_font, width=40)
        self.ent_key_dec.grid(row=3, column=1, columnspan=2, pady=5)
        
        btn_frame_dec_key = tk.Frame(self.frame_right)
        btn_frame_dec_key.grid(row=4, column=1, columnspan=2, sticky="e")
        tk.Button(btn_frame_dec_key, text="📂 Tải Khóa", bg="#1976D2", fg="white", font=self.bold_font, width=10, command=self.load_key_dec).pack(side="left", padx=5)
        tk.Button(btn_frame_dec_key, text="Lưu Khóa", bg="#1976D2", fg="white", font=self.bold_font, width=10, command=lambda: self.save_file(self.ent_key_dec.get())).pack(side="left")

        # Tùy chọn Định dạng đầu vào
        tk.Label(self.frame_right, text="Định dạng đầu vào:", font=self.bold_font).grid(row=5, column=0, sticky="w", pady=5)
        self.cbb_format_dec = ttk.Combobox(self.frame_right, values=["Base64", "Hex"], state="readonly", width=37)
        self.cbb_format_dec.current(0)
        self.cbb_format_dec.grid(row=5, column=1, columnspan=2, pady=5)

        tk.Label(self.frame_right, text="Văn bản Giải Mã:", font=self.bold_font).grid(row=6, column=0, sticky="w", pady=5)
        self.txt_plain_dec = tk.Text(self.frame_right, height=4, width=40, font=self.default_font)
        self.txt_plain_dec.grid(row=6, column=1, columnspan=2, pady=5)

        action_frame_dec = tk.Frame(self.frame_right)
        action_frame_dec.grid(row=7, column=0, columnspan=3, pady=15)
        tk.Button(action_frame_dec, text="🔓 Giải mã", bg="#388E3C", fg="white", font=self.bold_font, width=12, command=self.decrypt_action).pack(side="left", padx=10)
        tk.Button(action_frame_dec, text="Xóa dữ liệu", bg="#D32F2F", fg="white", font=self.bold_font, width=12, command=lambda: self.clear_all("dec")).pack(side="left", padx=10)
        tk.Button(action_frame_dec, text="💾 Lưu kết quả", bg="#1976D2", fg="white", font=self.bold_font, width=12, command=lambda: self.save_file(self.txt_plain_dec.get("1.0", tk.END))).pack(side="left", padx=10)

    # ================= CÁC HÀM CHỨC NĂNG CHUNG =================
    # Sinh khóa ngẫu nhiên sử dụng thư viện secrets
    def generate_key(self):
        len_str = self.cbb_key_len_enc.get()
        length = 8 if "8" in len_str else (16 if "16" in len_str else 24)
        chars = string.ascii_letters + string.digits
        random_key = ''.join(secrets.choice(chars) for _ in range(length))
        
        self.ent_key_enc.delete(0, tk.END)
        self.ent_key_enc.insert(0, random_key)

    # Mở hộp thoại chọn file và đẩy nội dung vào Text Box
    def load_file(self, text_widget):
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    text_widget.delete("1.0", tk.END)
                    text_widget.insert(tk.END, file.read())
            except Exception as e:
                messagebox.showerror("Lỗi", f"Không thể đọc file: {e}")
    
    # Tải khóa từ file cho ô nhập khóa Giải mã
    def load_key_dec(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    self.ent_key_dec.delete(0, tk.END)
                    self.ent_key_dec.insert(0, file.read().strip())
            except Exception as e:
                messagebox.showerror("Lỗi", f"Không thể đọc khóa: {e}")

    # Lưu nội dung ra file text
    def save_file(self, content):
        content = content.strip()
        if not content:
            messagebox.showwarning("Cảnh báo", "Không có dữ liệu để lưu!")
            return
        
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as file:
                    file.write(content)
                messagebox.showinfo("Thành công", f"Đã lưu thành công vào:\n{os.path.basename(file_path)}")
            except Exception as e:
                messagebox.showerror("Lỗi", f"Không thể lưu file: {e}")

    # Xóa dữ liệu trên form một cách gọn gàng
    def clear_all(self, side):
        widgets = (
            [self.txt_plain_enc, self.ent_key_enc, self.txt_cipher_enc] 
            if side == "enc" else 
            [self.txt_cipher_dec, self.ent_key_dec, self.txt_plain_dec]
        )
        for widget in widgets:
            if isinstance(widget, tk.Text):
                widget.delete("1.0", tk.END)
            else:
                widget.delete(0, tk.END)

    # Chuẩn hóa Khóa: Mật mã DES/3DES
    def get_valid_key(self, key: str, req_len: int) -> bytes:
        if not key:
            messagebox.showwarning("Cảnh báo", "Vui lòng nhập khóa (Key)!")
            return b""
        
        key_bytes = key.encode('utf-8')
        return key_bytes.ljust(req_len, b' ')[:req_len]

    # ================= CHỨC NĂNG MÃ HÓA & GIẢI MÃ =================
    def encrypt_action(self):
        txt = self.txt_plain_enc.get("1.0", tk.END).strip()
        if not txt:
            messagebox.showwarning("Cảnh báo", "Vui lòng nhập văn bản gốc!")
            return

        # Đọc độ dài khóa và định dạng
        len_str = self.cbb_key_len_enc.get()
        req_len = 8 if "8" in len_str else (16 if "16" in len_str else 24)
        out_format = self.cbb_format_enc.get()

        key_bytes = self.get_valid_key(self.ent_key_enc.get(), req_len)
        if not key_bytes: return

        try:
            padded_txt = pad(txt.encode('utf-8'), DES.block_size)
            
            # Chọn thuật toán dựa trên độ dài khóa
            if req_len == 8:
                cipher = DES.new(key_bytes, DES.MODE_ECB)
            else:
                cipher = DES3.new(key_bytes, DES3.MODE_ECB)
                
            encrypted_bytes = cipher.encrypt(padded_txt)

            # Xử lý định dạng đầu ra
            if out_format == "Base64":
                encrypted_result = base64.b64encode(encrypted_bytes).decode('utf-8')
            else:
                encrypted_result = encrypted_bytes.hex().upper()

            self.txt_cipher_enc.delete("1.0", tk.END)
            self.txt_cipher_enc.insert(tk.END, encrypted_result)
            messagebox.showinfo("Thông báo", "Mã hóa thành công!")
            
            # Tự động copy sang bên giải mã để test nhanh
            self.txt_cipher_dec.delete("1.0", tk.END)
            self.txt_cipher_dec.insert(tk.END, encrypted_result)
            
            self.ent_key_dec.delete(0, tk.END)
            self.ent_key_dec.insert(0, self.ent_key_enc.get())
            
            self.cbb_key_len_dec.set(len_str)
            self.cbb_format_dec.set(out_format)

        except ValueError as ve:
            messagebox.showerror("Lỗi Khóa", f"Lỗi mật mã học (khóa yếu hoặc không hợp lệ): {ve}")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Có lỗi khi mã hóa:\n{e}")

    def decrypt_action(self):
        txt_in = self.txt_cipher_dec.get("1.0", tk.END).strip()
        if not txt_in:
            messagebox.showwarning("Cảnh báo", "Vui lòng nhập văn bản mã hóa!")
            return

        # Đọc độ dài khóa và định dạng
        len_str = self.cbb_key_len_dec.get()
        req_len = 8 if "8" in len_str else (16 if "16" in len_str else 24)
        in_format = self.cbb_format_dec.get()

        key_bytes = self.get_valid_key(self.ent_key_dec.get(), req_len)
        if not key_bytes: return

        try:
            # Xử lý định dạng đầu vào
            if in_format == "Base64":
                encrypted_bytes = base64.b64decode(txt_in.encode('utf-8'))
            else:
                encrypted_bytes = bytes.fromhex(txt_in)

            # Chọn thuật toán
            if req_len == 8:
                cipher = DES.new(key_bytes, DES.MODE_ECB)
            else:
                cipher = DES3.new(key_bytes, DES3.MODE_ECB)
            
            decrypted_bytes = cipher.decrypt(encrypted_bytes)
            decrypted_txt = unpad(decrypted_bytes, DES.block_size).decode('utf-8')

            self.txt_plain_dec.delete("1.0", tk.END)
            self.txt_plain_dec.insert(tk.END, decrypted_txt)
            messagebox.showinfo("Thông báo", "Giải mã thành công!")

        except ValueError as e:
            messagebox.showerror("Lỗi", "Sai khóa, dữ liệu Hex/Base64 không hợp lệ hoặc padding bị hỏng!")
        except KeyError as e:
            messagebox.showerror("Lỗi", "Khóa hoặc dữ liệu bị hỏng!")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Lỗi không xác định:\n{e}")

if __name__ == "__main__":
    app = DESApp()
    app.mainloop()