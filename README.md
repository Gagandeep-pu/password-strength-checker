🔐 Password Strength Checker

A sleek Python-based application that evaluates password strength in real-time using a Tkinter graphical interface.
It analyzes length, character variety, and entropy to help users create stronger and more secure passwords.

🚀 Features

✅ Real-time password strength evaluation
✅ Entropy calculation in bits
✅ Visual strength meter (green/red)
✅ Shows missing criteria (uppercase, lowercase, digits, symbols)
✅ Tips for improving weak passwords
✅ Copy-to-clipboard report
✅ Show/Hide password toggle
✅ Fully offline — no data is sent anywhere
✅ Runs on Windows, Linux (Kali included), and macOS

🖥️ GUI Highlights

Black hacker-style theme

Green success indicators

Red warning indicators

Clean & minimal layout

Organized into:

Strength meter

Criteria section

Entropy info

Tips panel

📊 How It Works

The tool checks your password against:

Length

Use of uppercase characters

Use of lowercase characters

Use of digits

Use of special symbols

It then:

Scores the password

Estimates entropy

Shows visual rating

Provides improvement tips

🧠 Scoring & Entropy

Longer passwords = higher score

More character types = higher score

Entropy shows how resistant a password is to guessing

60–80 bits recommended for general accounts

📁 Installation
✅ Requirements

Python 3.x

✅ Run
python3 pwstrength_gui_black.py


No additional libraries required — only math, re, and tkinter.
