import tkinter as tk
import re
import random
import string

class PasswordAnalyzerPro:
    def __init__(self, root):
        self.root = root
        self.root.title("SecurePass Analyzer")
        self.root.geometry("600x650")
        self.root.configure(bg="#1c2c44")
        
        self.show_pass = False

        # UI Header
        tk.Label(root, text="SecurePass Analyzer", fg="white", bg="#1c2c44", 
                 font=("Arial", 24, "bold")).pack(pady=(40, 5))
        tk.Label(root, text="Check and generate industry-standard passwords", fg="#8896a6", 
                 bg="#1c2c44", font=("Arial", 10)).pack(pady=(0, 20))

        # Input Area
        self.entry_frame = tk.Frame(root, bg="white", padx=15, pady=8)
        self.entry_frame.pack(pady=10, padx=60, fill="x")

        self.password_var = tk.StringVar()
        self.password_var.trace_add("write", self.analyze)
        
        self.entry = tk.Entry(self.entry_frame, textvariable=self.password_var, show="*",
                             font=("Arial", 14), bg="white", fg="#333", relief="flat", borderwidth=0)
        self.entry.pack(side="left", fill="x", expand=True)

        self.eye_btn = tk.Label(self.entry_frame, text="👁", bg="white", fg="gray", cursor="hand2", font=("Arial", 14))
        self.eye_btn.pack(side="right")
        self.eye_btn.bind("<Button-1>", self.toggle_visibility)

        #1. Ko nsistensi Istilah (Weak, Fair, Good, Strong)
        labels_frame = tk.Frame(root, bg="#1c2c44")
        labels_frame.pack(fill="x", padx=60, pady=(15, 0))
        self.levels = ["Weak", "Fair", "Good", "Strong"]
        
        for txt in self.levels:
            tk.Label(labels_frame, text=txt, fg="#bdc3c7", bg="#1c2c44", width=12, font=("Arial", 9)).pack(side="left", expand=True)

        self.canvas = tk.Canvas(root, height=12, bg="#34495e", highlightthickness=0)
        self.canvas.pack(fill="x", padx=60, pady=(5, 10))
        self.segments = [self.canvas.create_rectangle(0, 0, 0, 0, fill="#444", outline="#1c2c44") for _ in range(4)]

        # 2. Inline Feedback Status 
        self.status_label = tk.Label(root, text="Waiting for input...", fg="#bdc3c7", 
                                     bg="#2c3e50", font=("Arial", 10, "italic"), pady=8)
        self.status_label.pack(fill="x", padx=60, pady=10)

        # Requirements Checklist
        tk.Label(root, text="Security Requirements:", fg="white", bg="#1c2c44", 
                 font=("Arial", 12, "bold")).pack(anchor="w", padx=60, pady=(20, 10))

        self.criteria_list = [
            ("len", "At least 12 characters long"),
            ("case", "Mix of uppercase and lowercase"),
            ("num", "Contains numbers (0-9)"),
            ("sym", "Contains special symbols")
        ]
        self.tip_widgets = {}

        for key, text in self.criteria_list:
            f = tk.Frame(root, bg="#1c2c44")
            f.pack(fill="x", padx=60, pady=4)
            icon = tk.Label(f, text="○", fg="#7f8c8d", bg="#1c2c44", font=("Arial", 14))
            icon.pack(side="left")
            lbl = tk.Label(f, text=text, fg="#ecf0f1", bg="#1c2c44", font=("Arial", 11))
            lbl.pack(side="left", padx=15)
            self.tip_widgets[key] = icon

        # Buttons
        self.button_container = tk.Frame(root, bg="#1c2c44")
        self.button_container.pack(side="bottom", fill="x", padx=60, pady=40)

        self.gen_btn = tk.Button(self.button_container, text="Generate", bg="#3498db", fg="white",
                                 font=("Arial", 11, "bold"), relief="flat", padx=15, pady=8, command=self.generate_pass)
        self.gen_btn.pack(side="left", expand=True, fill="x", padx=2)

        self.copy_btn = tk.Button(self.button_container, text="Copy", bg="#2ecc71", fg="white",
                                 font=("Arial", 11, "bold"), relief="flat", padx=15, pady=8, command=self.copy_to_clipboard)
        self.copy_btn.pack(side="left", expand=True, fill="x", padx=2)

        self.clear_btn = tk.Button(self.button_container, text="Reset", bg="#e74c3c", fg="white",
                                  font=("Arial", 11, "bold"), relief="flat", padx=15, pady=8, command=self.reset_ui)
        self.clear_btn.pack(side="left", expand=True, fill="x", padx=2)

        self.root.bind("<Configure>", self.draw_segments)

    def draw_segments(self, event=None):
        w = self.canvas.winfo_width()
        seg_w = w / 4
        for i, s in enumerate(self.segments):
            self.canvas.coords(s, i*seg_w, 0, (i+1)*seg_w, 12)

    def toggle_visibility(self, event):
        self.show_pass = not self.show_pass
        self.entry.config(show="" if self.show_pass else "*")

    def copy_to_clipboard(self):
        pwd = self.password_var.get()
        if pwd:
            self.root.clipboard_clear()
            self.root.clipboard_append(pwd)
            # Inline Feedback Replacement for Messagebox
            self.status_label.config(text="Password copied to clipboard ✅", fg="#2ecc71")
        else:
            self.status_label.config(text="Nothing to copy! ❌", fg="#e74c3c")

    def generate_pass(self):
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        pwd = "".join(random.choice(chars) for _ in range(16))
        self.password_var.set(pwd)
        self.status_label.config(text="New password generated ✨", fg="#3498db")

    def reset_ui(self):
        self.password_var.set("")
        self.status_label.config(text="Waiting for input...", fg="#bdc3c7")

    # 3. Logika Analisis dengan Komentar 
    def analyze(self, *args):
        pwd = self.password_var.get()
        if not pwd:
            self.update_visuals(0, {})
            return

        # Kriteria Keamanan: Panjang, Variasi Huruf, Angka, dan Simbol
        checks = {
            "len": len(pwd) >= 12,
            "case": any(c.isupper() for c in pwd) and any(c.islower() for c in pwd),
            "num": any(c.isdigit() for c in pwd),
            "sym": bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', pwd))
        }

        # Hitung skor dasar (0-4)
        score = sum(checks.values())

        # Password di bawah 8 karakter dianggap tidak aman
        if len(pwd) < 8: 
            score = min(score, 1) 
        
        self.update_visuals(score, checks)

    def update_visuals(self, score, checks):
        colors = ["#e74c3c", "#f39c12", "#f1c40f", "#2ecc71"]
        
        # Sinkronisasi warna bar dan ikon checklist
        for i in range(4):
            fill = colors[i] if i < score else "#444"
            self.canvas.itemconfig(self.segments[i], fill=fill)

        for key, text in self.criteria_list:
            met = checks.get(key, False)
            self.tip_widgets[key].config(text="✔" if met else "○", 
                                         fg="#2ecc71" if met else "#e74c3c")

        # Sinkronisasi Label Status dengan Label Bar 
        if score > 0:
            current_status = self.levels[score-1]
            self.status_label.config(text=f"Strength Status: {current_status}", fg="white")
        else:
            self.status_label.config(text="Strength Status: Critical (Too Short)", fg="#e74c3c")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordAnalyzerPro(root)
    root.mainloop()