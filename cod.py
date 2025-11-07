#!/usr/bin/env python3
import math
import re
import tkinter as tk
from tkinter import messagebox

# --- Rules / regex ---
UPPER = re.compile(r'[A-Z]')
LOWER = re.compile(r'[a-z]')
DIGIT = re.compile(r'[0-9]')
SPECIAL = re.compile(r'[^A-Za-z0-9]')

MIN_LEN_OK = 8
MIN_LEN_STRONG = 12

# --- Scoring / entropy ---
def estimate_entropy_bits(pw: str) -> float:
    if not pw:
        return 0.0
    charset = 0
    if UPPER.search(pw): charset += 26
    if LOWER.search(pw): charset += 26
    if DIGIT.search(pw): charset += 10
    if SPECIAL.search(pw): charset += 33  # approx printable non-alnum
    if charset == 0:
        charset = 1
    return len(pw) * math.log2(charset)

def score_password(pw: str):
    length = len(pw)
    has_upper = bool(UPPER.search(pw))
    has_lower = bool(LOWER.search(pw))
    has_digit = bool(DIGIT.search(pw))
    has_special = bool(SPECIAL.search(pw))

    # Points: length (0–3), variety (0–4)
    if length >= 16:
        length_pts = 3
    elif length >= MIN_LEN_STRONG:
        length_pts = 2
    elif length >= MIN_LEN_OK:
        length_pts = 1
    else:
        length_pts = 0

    variety_pts = sum([has_upper, has_lower, has_digit, has_special])
    total = length_pts + variety_pts
    max_points = 7

    if total <= 2:
        rating = "Very Weak"
    elif total == 3:
        rating = "Weak"
    elif total in (4, 5):
        rating = "Moderate"
    elif total == 6:
        rating = "Strong"
    else:
        rating = "Very Strong"

    entropy = estimate_entropy_bits(pw)

    return {
        "length": length,
        "has_upper": has_upper,
        "has_lower": has_lower,
        "has_digit": has_digit,
        "has_special": has_special,
        "length_points": length_pts,
        "variety_points": variety_pts,
        "total_points": total,
        "max_points": max_points,
        "rating": rating,
        "entropy_bits": entropy,
    }

# --- GUI (black bg, green/red text) ---
BG = "#000000"     # black
FG_GREEN = "#00ff6a"
FG_RED = "#ff3b3b"
FG_DIM = "#9ae7c0"

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Strength Checker")
        self.configure(bg=BG)
        self.geometry("560x420")
        self.minsize(520, 380)

        # Title
        self.lbl_title = tk.Label(self, text="Password Strength Checker",
                                  font=("Segoe UI", 16, "bold"),
                                  bg=BG, fg=FG_GREEN)
        self.lbl_title.pack(anchor="w", padx=14, pady=(12, 8))

        # Input row
        row = tk.Frame(self, bg=BG)
        row.pack(fill="x", padx=14, pady=(0, 8))

        tk.Label(row, text="Password:", bg=BG, fg=FG_DIM).pack(side="left")
        self.var_pw = tk.StringVar()
        self.entry_pw = tk.Entry(row, textvariable=self.var_pw, show="•",
                                 bg=BG, fg=FG_GREEN, insertbackground=FG_GREEN,
                                 relief="solid", highlightthickness=1,
                                 highlightbackground=FG_DIM, highlightcolor=FG_GREEN)
        self.entry_pw.pack(side="left", fill="x", expand=True, padx=8)
        self.entry_pw.bind("<KeyRelease>", self.on_change)
        self.entry_pw.bind("<FocusIn>", self.on_change)

        self.show_var = tk.BooleanVar(value=False)
        self.chk_show = tk.Checkbutton(row, text="Show", variable=self.show_var,
                                       command=self.toggle_show, bg=BG,
                                       activebackground=BG, fg=FG_DIM,
                                       selectcolor=BG, highlightthickness=0)
        self.chk_show.pack(side="left")

        # Meter
        meter = tk.Frame(self, bg=BG)
        meter.pack(fill="x", padx=14, pady=(0, 6))
        tk.Label(meter, text="Strength:", bg=BG, fg=FG_DIM).pack(anchor="w")

        self.canvas = tk.Canvas(meter, height=18, bg=BG, highlightthickness=1,
                                highlightbackground=FG_DIM)
        self.canvas.pack(fill="x", expand=True)
        self.rating_lbl = tk.Label(meter, text="—", bg=BG, fg=FG_GREEN)
        self.rating_lbl.pack(anchor="e", pady=(4, 0))

        # Criteria
        crit = tk.LabelFrame(self, text="Criteria", bg=BG, fg=FG_GREEN,
                             highlightthickness=1, bd=1, labelanchor="nw")
        crit.pack(fill="x", padx=14, pady=(6, 6))

        self.lbl_len = tk.Label(crit, text="Length (≥ 8)", bg=BG, fg=FG_RED)
        self.lbl_up  = tk.Label(crit, text="Uppercase (A–Z)", bg=BG, fg=FG_RED)
        self.lbl_lo  = tk.Label(crit, text="Lowercase (a–z)", bg=BG, fg=FG_RED)
        self.lbl_di  = tk.Label(crit, text="Digits (0–9)", bg=BG, fg=FG_RED)
        self.lbl_sp  = tk.Label(crit, text="Special (!@#$…)", bg=BG, fg=FG_RED)

        for w in (self.lbl_len, self.lbl_up, self.lbl_lo, self.lbl_di, self.lbl_sp):
            w.pack(anchor="w", pady=2, padx=8)

        # Details
        details = tk.LabelFrame(self, text="Details", bg=BG, fg=FG_GREEN,
                                highlightthickness=1, bd=1, labelanchor="nw")
        details.pack(fill="both", expand=True, padx=14, pady=(6, 0))

        self.entropy_lbl = tk.Label(details, text="Estimated entropy: 0.0 bits",
                                    bg=BG, fg=FG_DIM)
        self.entropy_lbl.pack(anchor="w", pady=(6, 6), padx=8)

        self.tips = tk.Text(details, height=6, wrap="word",
                            bg=BG, fg=FG_RED, insertbackground=FG_GREEN)
        self.tips.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.tips.configure(state="disabled")

        # Buttons
        btns = tk.Frame(self, bg=BG)
        btns.pack(fill="x", padx=14, pady=(8, 12))
        tk.Button(btns, text="Clear", command=self.clear,
                  bg=BG, fg=FG_GREEN, activebackground="#111", activeforeground=FG_GREEN,
                  relief="ridge").pack(side="left")
        tk.Button(btns, text="Copy Report", command=self.copy_report,
                  bg=BG, fg=FG_GREEN, activebackground="#111", activeforeground=FG_GREEN,
                  relief="ridge").pack(side="right")

        # First compute
        self.after(50, self.compute)

    # --- UI helpers ---
    def toggle_show(self):
        self.entry_pw.config(show="" if self.show_var.get() else "•")

    def on_change(self, _=None):
        self.compute()

    def set_meter(self, total_points, max_points, rating):
        # Draw a simple bar that turns red/green based on percentage
        w = self.canvas.winfo_width() or self.canvas.winfo_reqwidth()
        percent = (total_points / max_points) if max_points else 0
        self.canvas.delete("all")
        # background track
        self.canvas.create_rectangle(1, 1, w-1, 17, outline=FG_DIM)
        fill_w = int((w-2) * percent)
        color = FG_RED if percent < 0.6 else FG_GREEN
        if fill_w > 0:
            self.canvas.create_rectangle(2, 2, 2 + fill_w, 16, outline=color, fill=color)
        self.rating_lbl.config(text=f"{rating}  ({int(percent*100)}%)",
                               fg=(FG_RED if percent < 0.6 else FG_GREEN))

    def set_checks(self, res):
        def set_fg(label, ok):
            label.config(fg=(FG_GREEN if ok else FG_RED))
        set_fg(self.lbl_len, res["length"] >= MIN_LEN_OK)
        set_fg(self.lbl_up,  res["has_upper"])
        set_fg(self.lbl_lo,  res["has_lower"])
        set_fg(self.lbl_di,  res["has_digit"])
        set_fg(self.lbl_sp,  res["has_special"])

    def build_tips(self, res):
        tips = []
        if res["length"] < MIN_LEN_OK:
            tips.append(f"Increase length to at least {MIN_LEN_OK} characters; {MIN_LEN_STRONG}+ is better.")
        elif res["length"] < MIN_LEN_STRONG:
            tips.append(f"Consider {MIN_LEN_STRONG}+ characters for stronger resistance to guessing.")
        if not res["has_upper"]: tips.append("Add uppercase letters (A–Z).")
        if not res["has_lower"]: tips.append("Add lowercase letters (a–z).")
        if not res["has_digit"]: tips.append("Include digits (0–9).")
        if not res["has_special"]: tips.append("Include special characters (e.g., !@#$%).")
        if res["entropy_bits"] < 50:
            tips.append("Aim for ~60–80 bits of entropy for general accounts; more for high-value targets.")
        if not tips:
            tips.append("Looks solid. Consider a 4–6 word random passphrase for memorability.")
        return "• " + "\n• ".join(tips)

    def compute(self):
        pw = self.var_pw.get()
        res = score_password(pw)
        self.set_meter(res["total_points"], res["max_points"], res["rating"])
        self.set_checks(res)
        self.entropy_lbl.config(text=f"Estimated entropy: {res['entropy_bits']:.1f} bits")
        # tips
        self.tips.configure(state="normal")
        self.tips.delete("1.0", "end")
        self.tips.insert("1.0", self.build_tips(res))
        self.tips.configure(state="disabled")

    def clear(self):
        self.var_pw.set("")
        self.compute()

    def copy_report(self):
        pw = self.var_pw.get()
        res = score_password(pw)
        report = (
            f"Password report\n"
            f"----------------\n"
            f"Length: {res['length']}\n"
            f"Uppercase: {'yes' if res['has_upper'] else 'no'}\n"
            f"Lowercase: {'yes' if res['has_lower'] else 'no'}\n"
            f"Digits: {'yes' if res['has_digit'] else 'no'}\n"
            f"Special: {'yes' if res['has_special'] else 'no'}\n"
            f"Score: {res['total_points']}/{res['max_points']} → {res['rating']}\n"
            f"Estimated entropy: {res['entropy_bits']:.1f} bits\n"
        )
        self.clipboard_clear()
        self.clipboard_append(report)
        messagebox.showinfo("Copied", "Report copied to clipboard.")

if __name__ == "__main__":
    app = App()
    # Ensure canvas resizes draws correctly
    app.canvas.bind("<Configure>", lambda e: app.compute())
    app.mainloop()
