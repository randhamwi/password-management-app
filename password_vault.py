import sqlite3
import hashlib
import tkinter as tk
from tkinter import simpledialog, messagebox
from functools import partial
import uuid
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import secrets
import string
from datetime import datetime
import clipboard
import pyotp 
import qrcode
from PIL import Image, ImageTk
import os
import passwordmeter

# إعدادات التصميم الغامق المحسّن
APP_NAME = "SecurePass Manager"
DARK_BG = "#0f0f1a"  # أزرق غامق جداً
DARK_FG = "#e0e0ff"  # أزرق فاتح للنص
ACCENT_COLOR = "#6c5ce7"  # أرجواني فاتح
SECONDARY_COLOR = "#00cec9"  # تركوازي فاتح
WARNING_COLOR = "#ff7675"  # أحمر فاتح
SUCCESS_COLOR = "#55efc4"  # أخضر فاتح
GENERATE_COLOR = "#fdcb6e"  # أصفر فاتح
ENTRY_BG = "#1a1a2e"  # أزرق داكن للحقول
BUTTON_BG = "#341f97"  # أزرق داكن للأزرار
BUTTON_HOVER = "#5f27cd"  # أزرق أرجواني
FONT = ("Segoe UI", 11)
TITLE_FONT = ("Segoe UI", 16, "bold")
HEADER_FONT = ("Segoe UI", 20, "bold")

# إنشاء مجلد لرموز QR إذا لم يكن موجوداً
os.makedirs("qrcodes", exist_ok=True)

# إعدادات تشفير المفاتيح
backend = default_backend()
salt = b"securepass_salt"

def kdf(pw):
    """دالة لاشتقاق مفتاح تشفير من كلمة المرور"""
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend,
    ).derive(pw.encode())

# إعداد قاعدة البيانات
db = sqlite3.connect("securepass.db")
cursor = db.cursor()

# إنشاء جدول المستخدمين
cursor.execute(
    """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT ,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    recoveryKey TEXT NOT NULL,
    masterKeyEncrypted TEXT NOT NULL,
    recoveryKeyEncrypted TEXT NOT NULL,
    secret TEXT
);
""")

# إنشاء جدول كلمات المرور
cursor.execute(
    """
CREATE TABLE IF NOT EXISTS vault (
    id INTEGER PRIMARY KEY AUTOINCREMENT ,
    user_id INTEGER NOT NULL,
    website TEXT NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL
);
""")

# إنشاء جدول سجلات الأنشطة
cursor.execute(
    """
CREATE TABLE IF NOT EXISTS activity_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT ,
    user_id INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    activity TEXT NOT NULL
);
""")
db.commit()

# المستخدم الحالي
current_user = {
    "id": None,
    "encryptionKey": None,
    "old_encryptionKey": None  # إضافة لحفظ المفتاح القديم
}

def log_activity(activity: str):
    """تسجيل نشاط المستخدم في قاعدة البيانات"""
    user_id = current_user.get("id")
    if user_id is None:  # إذا لم يكن هناك مستخدم مسجل دخوله
        return  # لا تسجل النشاط
    cursor.execute(
        "INSERT INTO activity_log (user_id, timestamp, activity) VALUES (?, ?, ?)",
        (user_id, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), activity),
    )
    db.commit()

def encrypt(message: bytes, key: bytes) -> bytes:
    """تشفير البيانات باستخدام مفتاح معين"""
    return Fernet(key).encrypt(message)

def decrypt(message: bytes, key: bytes) -> bytes:
    """فك تشفير البيانات باستخدام مفتاح معين"""
    return Fernet(key).decrypt(message)

def hashPassword(input_string):
    """تجزئة كلمة المرور باستخدام خوارزمية SHA-256"""
    return hashlib.sha256(input_string.encode("utf-8")).hexdigest()

def apply_dark_theme(widget):
    """تطبيق السمة الغامقة على عناصر الواجهة"""
    try:
        if hasattr(widget, 'configure'):
            if 'bg' in widget.keys():
                widget.configure(bg=DARK_BG)
            if 'fg' in widget.keys():
                widget.configure(fg=DARK_FG)
            
            if isinstance(widget, tk.Button):
                widget.configure(
                    bg=BUTTON_BG, 
                    fg=DARK_FG,
                    activebackground=BUTTON_HOVER,
                    activeforeground=DARK_FG,
                    relief="flat",
                    padx=12,
                    pady=6,
                    border=0,
                    font=FONT
                )
            elif isinstance(widget, tk.Entry):
                widget.configure(
                    bg=ENTRY_BG, 
                    fg=DARK_FG,
                    insertbackground=DARK_FG,
                    relief="flat",
                    font=FONT
                )
            elif isinstance(widget, tk.Label):
                widget.configure(bg=DARK_BG, fg=DARK_FG, font=FONT)
            elif isinstance(widget, tk.Frame):
                widget.configure(bg=DARK_BG)
    except tk.TclError:
        pass
    
    for child in widget.winfo_children():
        apply_dark_theme(child)

def create_rounded_button(parent, text, command, bg=BUTTON_BG, fg=DARK_FG, **kwargs):
    """إنشاء زر بتصميم دائري"""
    btn = tk.Button(
        parent, 
        text=text, 
        command=command,
        bg=bg,
        fg=fg,
        bd=0,
        padx=15,
        pady=7,
        relief="flat",
        font=FONT,
        **kwargs
    )
    return btn

def generate_password(length=16, uppercase=True, lowercase=True, digits=True, symbols=True):
    """إنشاء كلمة مرور قوية وعشوائية مع خيارات متقدمة"""
    characters = ""
    if uppercase:
        characters += string.ascii_uppercase
    if lowercase:
        characters += string.ascii_lowercase
    if digits:
        characters += string.digits
    if symbols:
        characters += string.punctuation
        
    if not characters:
        return ""
    
    for _ in range(100):  # محاولات كافية
        password = ''.join(secrets.choice(characters) for i in range(length))
        strength, _ = passwordmeter.test(password)
        if strength >= 0.7:  # إذا كانت القوة 70% أو أكثر
            return password
        
    return ''.join(secrets.choice(characters) for i in range(length))

def show_password_generator():
    """عرض شاشة إنشاء كلمات مرور متقدمة"""
    log_activity("Accessed password generator")
    generator = tk.Toplevel(window)
    generator.title(f"{APP_NAME} - Password Generator")
    generator.geometry("450x450")
    generator.configure(bg=DARK_BG)
    
    main_frame = tk.Frame(generator, bg=DARK_BG)
    main_frame.pack(fill="both", expand=True, padx=25, pady=25)
    
    title = tk.Label(
        main_frame, 
        text="Password Generator", 
        font=HEADER_FONT,
        bg=DARK_BG,
        fg=ACCENT_COLOR
    )
    title.pack(pady=10)
    
    # إطار الخيارات
    options_frame = tk.LabelFrame(
        main_frame, 
        text="Password Options",
        bg=DARK_BG,
        fg=SECONDARY_COLOR,
        font=("Segoe UI", 12, "bold"),
        padx=10,
        pady=10
    )
    options_frame.pack(fill="x", pady=15)
    
    # طول كلمة المرور
    tk.Label(
        options_frame, 
        text="Password Length:", 
        bg=DARK_BG, 
        fg=DARK_FG,
        font=FONT
    ).grid(row=0, column=0, sticky="w", padx=5, pady=5)
    
    length_var = tk.IntVar(value=16)
    length_spin = tk.Spinbox(
        options_frame, 
        from_=8, 
        to=32, 
        width=5,
        textvariable=length_var,
        font=FONT,
        bg=ENTRY_BG,
        fg=DARK_FG
    )
    length_spin.grid(row=0, column=1, padx=5, pady=5)
    
    # خيارات الأحرف
    uppercase_var = tk.BooleanVar(value=True)
    lowercase_var = tk.BooleanVar(value=True)
    digits_var = tk.BooleanVar(value=True)
    symbols_var = tk.BooleanVar(value=True)
    
    tk.Checkbutton(
        options_frame, 
        text="Uppercase Letters (A-Z)", 
        variable=uppercase_var,
        bg=DARK_BG,
        fg=DARK_FG,
        selectcolor=DARK_BG,
        activebackground=DARK_BG,
        activeforeground=DARK_FG,
        font=FONT
    ).grid(row=1, column=0, columnspan=2, sticky="w", padx=5, pady=3)
    
    tk.Checkbutton(
        options_frame, 
        text="Lowercase Letters (a-z)", 
        variable=lowercase_var,
        bg=DARK_BG,
        fg=DARK_FG,
        selectcolor=DARK_BG,
        activebackground=DARK_BG,
        activeforeground=DARK_FG,
        font=FONT
    ).grid(row=2, column=0, columnspan=2, sticky="w", padx=5, pady=3)
    
    tk.Checkbutton(
        options_frame, 
        text="Digits (0-9)", 
        variable=digits_var,
        bg=DARK_BG,
        fg=DARK_FG,
        selectcolor=DARK_BG,
        activebackground=DARK_BG,
        activeforeground=DARK_FG,
        font=FONT
    ).grid(row=3, column=0, columnspan=2, sticky="w", padx=5, pady=3)
    
    tk.Checkbutton(
        options_frame, 
        text="Symbols (!@#$%^&*)", 
        variable=symbols_var,
        bg=DARK_BG,
        fg=DARK_FG,
        selectcolor=DARK_BG,
        activebackground=DARK_BG,
        activeforeground=DARK_FG,
        font=FONT
    ).grid(row=4, column=0, columnspan=2, sticky="w", padx=5, pady=3)
    
    # حقل عرض كلمة المرور
    password_frame = tk.Frame(main_frame, bg=DARK_BG)
    password_frame.pack(fill="x", pady=15)
    
    password_var = tk.StringVar()
    password_entry = tk.Entry(
        password_frame, 
        textvariable=password_var,
        width=30,
        font=("Segoe UI", 14),
        bg=ENTRY_BG,
        fg=SECONDARY_COLOR,
        justify="center",
        relief="flat",
        bd=0
    )
    password_entry.pack(pady=5, fill="x", padx=5)
    
    # قوة كلمة المرور
    strength_var = tk.StringVar(value="Password Strength: -")
    strength_label = tk.Label(
        password_frame, 
        textvariable=strength_var,
        font=("Segoe UI", 10),
        bg=DARK_BG,
        fg=DARK_FG
    )
    strength_label.pack(pady=3)
    
    # أزرار التحكم
    button_frame = tk.Frame(main_frame, bg=DARK_BG)
    button_frame.pack(pady=10)
    
    def generate():
        length = int(length_var.get())
        password = generate_password(
            length,
            uppercase_var.get(),
            lowercase_var.get(),
            digits_var.get(),
            symbols_var.get()
        )
        password_var.set(password)
        
        # حساب قوة كلمة المرور
        strength, improvements = passwordmeter.test(password)
        
        strength_text = "Weak"
        color = WARNING_COLOR
        if strength >= 0.7:
            strength_text = "Very Strong"
            color = SUCCESS_COLOR
        elif strength >= 0.5:
            strength_text = "Strong"
            color = SECONDARY_COLOR
        elif strength >= 0.3:
            strength_text = "Medium"
            color = GENERATE_COLOR
        
        strength_var.set(f"Password Strength: {strength_text} ({strength*100:.0f}%)")
        strength_label.config(fg=color)
        log_activity("Generated new password")
    
    generate_btn = create_rounded_button(
        button_frame, 
        "Generate", 
        generate,
        bg=GENERATE_COLOR,
        fg=DARK_BG
    )
    generate_btn.pack(side="left", padx=10)
    
    def copy_password():
        clipboard.copy(password_var.get())
        messagebox.showinfo("Copied", "Password copied to clipboard!")
        log_activity("Copied generated password to clipboard")
    
    copy_btn = create_rounded_button(
        button_frame, 
        "Copy", 
        copy_password,
        bg=SECONDARY_COLOR,
        fg=DARK_BG
    )
    copy_btn.pack(side="left", padx=10)
    
    def close_generator():
        generator.destroy()
        log_activity("Closed password generator")
    
    close_btn = create_rounded_button(
        button_frame, 
        "Close", 
        close_generator,
        bg=WARNING_COLOR
    )
    close_btn.pack(side="left", padx=10)
    
    # تطبيق السمة الغامقة
    apply_dark_theme(generator)
    
    # إنشاء كلمة مرور أولية
    generate()

# شاشة تسجيل مستخدم جديد
def registerScreen():
    log_activity("Accessed registration screen")
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("500x400") 
    window.title(f"{APP_NAME} - Register")
    
    main_frame = tk.Frame(window, bg=DARK_BG)
    main_frame.pack(fill="both", expand=True, padx=30, pady=30)
    
    title = tk.Label(
        main_frame, 
        text="Create Account", 
        font=HEADER_FONT,
        bg=DARK_BG,
        fg=ACCENT_COLOR
    )
    title.pack(pady=15)
    
    form_frame = tk.Frame(main_frame, bg=DARK_BG)
    form_frame.pack(pady=10)
    
    tk.Label(
        form_frame, 
        text="Username", 
        bg=DARK_BG, 
        fg=DARK_FG,
        font=FONT
    ).grid(row=0, column=0, sticky="w", padx=5, pady=5)
    usernameEntry = tk.Entry(form_frame, width=25, font=FONT)
    usernameEntry.grid(row=1, column=0, padx=5, pady=5)
    
    tk.Label(
        form_frame, 
        text="Password", 
        bg=DARK_BG, 
        fg=DARK_FG,
        font=FONT
    ).grid(row=2, column=0, sticky="w", padx=5, pady=10)
    passwordEntry = tk.Entry(form_frame, width=25, show="*", font=FONT)
    passwordEntry.grid(row=3, column=0, padx=5, pady=5)
    
    tk.Label(
        form_frame, 
        text="Confirm Password", 
        bg=DARK_BG, 
        fg=DARK_FG,
        font=FONT
    ).grid(row=4, column=0, sticky="w", padx=5, pady=10)
    confirmEntry = tk.Entry(form_frame, width=25, show="*", font=FONT)
    confirmEntry.grid(row=5, column=0, padx=5, pady=5)
    
    recoveryKeyVar = tk.StringVar()
    recoveryLabel = tk.Label(
        main_frame, 
        textvariable=recoveryKeyVar, 
        font=FONT, 
        wraplength=400,
        bg=DARK_BG,
        fg=SECONDARY_COLOR,
        justify="center"
    )
    recoveryLabel.pack(pady=15)
    
    button_frame = tk.Frame(main_frame, bg=DARK_BG)
    button_frame.pack(pady=10)
    
    def saveUser():
        username = usernameEntry.get().strip()
        pw = passwordEntry.get()
        confirm = confirmEntry.get()

        if not username or not pw:
            messagebox.showerror("Error", "Username and password cannot be empty.")
            return

        if pw != confirm:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        hashedPassword = hashPassword(pw)
        recoveryKey = str(uuid.uuid4().hex).lower()
        hashedRecoveryKey = hashPassword(recoveryKey)

        masterKey = secrets.token_urlsafe(32)
        encryptedMasterKey = encrypt(
            masterKey.encode(), base64.urlsafe_b64encode(kdf(pw))
        )
        encryptedRecoveryKey = encrypt(
            masterKey.encode(), base64.urlsafe_b64encode(kdf(recoveryKey))
        )

        try:
            cursor.execute(
                "INSERT INTO users (username, password, recoveryKey, masterKeyEncrypted, recoveryKeyEncrypted) VALUES (?, ?, ?, ?, ?)",
                (
                    username,
                    hashedPassword,
                    hashedRecoveryKey,
                    encryptedMasterKey,
                    encryptedRecoveryKey,
                ),
            )
            db.commit()
            recoveryKeyVar.set(
                f"Recovery Key: {recoveryKey}\n\nIMPORTANT: Save this key in a safe place!"
            )
            copyButton.config(state="normal")
            log_activity(f"New user registered: {username}")
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Username already exists.")
            log_activity("Registration failed: username already exists")

    btnSave = create_rounded_button(button_frame, "Register", saveUser, bg=ACCENT_COLOR)
    btnSave.pack(side="left", padx=10)

    def copyRecoveryKey():
        clipboard.copy(recoveryKeyVar.get().split(": ")[1].split("\n")[0])
        messagebox.showinfo("Copied", "Recovery key copied to clipboard!")
        log_activity("Copied recovery key to clipboard")

    copyButton = create_rounded_button(
        button_frame, 
        "Copy Key", 
        copyRecoveryKey, 
        bg=SECONDARY_COLOR,
        state="disabled"
    )
    copyButton.pack(side="left", padx=10)

    def backToLogin():
        loginScreen()
        log_activity("Returned to login screen from registration")

    btnBack = create_rounded_button(
        button_frame, 
        "Back", 
        backToLogin,
        bg=WARNING_COLOR
    )
    btnBack.pack(side="left", padx=10)
    
    apply_dark_theme(main_frame)

# وظائف مصادقة الثنائية
def get_or_create_secret(user_id):
    cursor.execute("SELECT secret FROM users WHERE id = ?", (user_id,))
    secret = cursor.fetchone()
    
    if secret and secret[0]:
        return secret[0]
    
    new_secret = pyotp.random_base32()
    cursor.execute("UPDATE users SET secret = ? WHERE id = ?", (new_secret, user_id))
    db.commit()
    log_activity("Generated new MFA secret")
    return new_secret

def generate_qr_code(user_id, username):
    secret = get_or_create_secret(user_id)
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name=APP_NAME)
    qr_path = f"qrcodes/{username}_qrcode.png"
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    img.save(qr_path)
    log_activity("Generated MFA QR code")
    return qr_path, secret

def verify_otp(secret, user_otp):
    return pyotp.TOTP(secret).verify(user_otp)

def show_mfa_screen(username, user_id):
    log_activity("Accessed MFA setup screen")
    for widget in window.winfo_children():
        widget.destroy()
    
    window.title(f"{APP_NAME} - Two-Factor Authentication")
    window.geometry("500x500")
    
    main_frame = tk.Frame(window, bg=DARK_BG)
    main_frame.pack(fill="both", expand=True, padx=30, pady=30)
    
    title = tk.Label(
        main_frame, 
        text="Two-Factor Authentication", 
        font=HEADER_FONT,
        bg=DARK_BG,
        fg=ACCENT_COLOR
    )
    title.pack(pady=10)
    
    instruction = tk.Label(
        main_frame, 
        text="Scan the QR code with your authenticator app", 
        font=FONT,
        bg=DARK_BG,
        fg=DARK_FG,
        wraplength=400
    )
    instruction.pack(pady=5)
    
    qr_path, secret = generate_qr_code(user_id, username)
    
    try:
        qr_img = Image.open(qr_path)
        qr_img = qr_img.resize((220, 220), Image.Resampling.LANCZOS)
        qr_photo = ImageTk.PhotoImage(qr_img)
        qr_label = tk.Label(main_frame, image=qr_photo, bg=DARK_BG)
        qr_label.image = qr_photo
        qr_label.pack(pady=10)
    except Exception as e:
        print(f"Error loading QR code: {e}")
        error_label = tk.Label(
            main_frame, 
            text="QR Code Generation Failed",
            font=FONT,
            bg=DARK_BG,
            fg=WARNING_COLOR
        )
        error_label.pack(pady=10)
    
    code_frame = tk.Frame(main_frame, bg=DARK_BG)
    code_frame.pack(pady=15)
    
    tk.Label(
        code_frame, 
        text="Enter Authentication Code:", 
        font=FONT,
        bg=DARK_BG,
        fg=DARK_FG
    ).pack(pady=5)
    
    otp_entry = tk.Entry(
        code_frame, 
        font=("Segoe UI", 16), 
        width=10,
        justify="center",
        bg=ENTRY_BG,
        fg=SECONDARY_COLOR
    )
    otp_entry.pack(pady=5)
    
    status_label = tk.Label(
        main_frame, 
        text="", 
        font=FONT,
        bg=DARK_BG,
        fg=WARNING_COLOR
    )
    status_label.pack(pady=5)
    
    btn_frame = tk.Frame(main_frame, bg=DARK_BG)
    btn_frame.pack(pady=15)
    
    def check_otp():
        user_otp = otp_entry.get()
        if verify_otp(secret, user_otp):
            log_activity("MFA verification successful")
            vaultScreen()
        else:
            status_label.config(text="Invalid authentication code")
            log_activity("MFA verification failed")
    
    verify_btn = create_rounded_button(
        btn_frame, 
        "Verify", 
        check_otp,
        bg=ACCENT_COLOR
    )
    verify_btn.pack(side="left", padx=10)
    
    def cancel_mfa():
        loginScreen()
        log_activity("Cancelled MFA setup")
    
    cancel_btn = create_rounded_button(
        btn_frame, 
        "Cancel", 
        cancel_mfa,
        bg=WARNING_COLOR
    )
    cancel_btn.pack(side="left", padx=10)
    
    apply_dark_theme(main_frame)

# شاشة استعادة كلمة المرور
def resetScreen():
    log_activity("Accessed password reset screen")
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("500x350")
    window.title(f"{APP_NAME} - Password Recovery")
    
    main_frame = tk.Frame(window, bg=DARK_BG)
    main_frame.pack(fill="both", expand=True, padx=30, pady=30)
    
    title = tk.Label(
        main_frame, 
        text="Recover Account", 
        font=HEADER_FONT,
        bg=DARK_BG,
        fg=ACCENT_COLOR
    )
    title.pack(pady=15)
    
    instruction = tk.Label(
        main_frame, 
        text="Enter your username and recovery key", 
        font=FONT,
        bg=DARK_BG,
        fg=DARK_FG,
        wraplength=400
    )
    instruction.pack(pady=10)
    
    form_frame = tk.Frame(main_frame, bg=DARK_BG)
    form_frame.pack(pady=15)
    
    tk.Label(
        form_frame, 
        text="Username", 
        bg=DARK_BG, 
        fg=DARK_FG,
        font=FONT
    ).grid(row=0, column=0, sticky="w", padx=5, pady=5)
    username_entry = tk.Entry(form_frame, width=25, font=FONT)
    username_entry.grid(row=1, column=0, padx=5, pady=5)
    
    tk.Label(
        form_frame, 
        text="Recovery Key", 
        bg=DARK_BG, 
        fg=DARK_FG,
        font=FONT
    ).grid(row=2, column=0, sticky="w", padx=5, pady=10)
    recovery_entry = tk.Entry(form_frame, width=25, font=FONT)
    recovery_entry.grid(row=3, column=0, padx=5, pady=5)
    
    status_label = tk.Label(
        main_frame, 
        text="", 
        font=FONT,
        bg=DARK_BG,
        fg=WARNING_COLOR
    )
    status_label.pack(pady=10)
    
    button_frame = tk.Frame(main_frame, bg=DARK_BG)
    button_frame.pack(pady=15)
    
    def checkRecoveryKey():
        username = username_entry.get().strip()
        recoveryKeyInput = recovery_entry.get().strip().lower()
        
        if not username or not recoveryKeyInput:
            status_label.config(text="Please enter both username and recovery key")
            return
            
        hashedRecoveryKeyInput = hashPassword(recoveryKeyInput)
        cursor.execute(
            "SELECT * FROM users WHERE username = ? AND recoveryKey = ?", 
            (username, hashedRecoveryKeyInput)
        )
        user = cursor.fetchone()

        if user:
            global current_user
            current_user["id"] = user[0]
            
            # تخزين مفتاح الاسترداد مؤقتاً
            current_user["temp_recovery_key"] = recoveryKeyInput
            
            # فك تشفير المفتاح الرئيسي باستخدام مفتاح الاسترداد
            try:
                key_recovery = base64.urlsafe_b64encode(kdf(recoveryKeyInput))
                masterKey = decrypt(user[5], key_recovery).decode()
                
                # تخزين المفتاح القديم لإعادة تشفير البيانات
                current_user["old_encryptionKey"] = base64.urlsafe_b64encode(kdf(masterKey))
                log_activity(f"Recovery key verified for user: {username}")
            except:
                messagebox.showerror("Error", "Failed to decrypt master key")
                log_activity("Recovery key verification failed")
                return
            
            changePasswordScreen()
        else:
            status_label.config(text="Invalid username or recovery key")
            log_activity("Recovery attempt failed for username: {username}")
    
    btnCheck = create_rounded_button(
        button_frame, 
        "Verify Key", 
        checkRecoveryKey, 
        bg=ACCENT_COLOR
    )
    btnCheck.pack(side="left", padx=10)
    
    def backToLogin():
        loginScreen()
        log_activity("Returned to login screen from password reset")
    
    btnBack = create_rounded_button(
        button_frame, 
        "Back", 
        backToLogin,
        bg=WARNING_COLOR
    )
    btnBack.pack(side="left", padx=10)
    
    apply_dark_theme(main_frame)

# شاشة تغيير كلمة المرور
def changePasswordScreen():
    log_activity("Accessed password change screen")
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("500x400")  # زيادة الارتفاع لعرض مفتاح الاسترداد
    window.title(f"{APP_NAME} - Change Password")
    
    main_frame = tk.Frame(window, bg=DARK_BG)
    main_frame.pack(fill="both", expand=True, padx=30, pady=30)
    
    title = tk.Label(
        main_frame, 
        text="Change Password", 
        font=HEADER_FONT,
        bg=DARK_BG,
        fg=ACCENT_COLOR
    )
    title.pack(pady=15)
    
    form_frame = tk.Frame(main_frame, bg=DARK_BG)
    form_frame.pack(pady=10)
    
    tk.Label(
        form_frame, 
        text="New Password", 
        bg=DARK_BG, 
        fg=DARK_FG,
        font=FONT
    ).grid(row=0, column=0, sticky="w", padx=5, pady=5)
    pwEntry = tk.Entry(form_frame, width=25, show="*", font=FONT)
    pwEntry.grid(row=1, column=0, padx=5, pady=5)
    
    tk.Label(
        form_frame, 
        text="Confirm Password", 
        bg=DARK_BG, 
        fg=DARK_FG,
        font=FONT
    ).grid(row=2, column=0, sticky="w", padx=5, pady=10)
    confirmEntry = tk.Entry(form_frame, width=25, show="*", font=FONT)
    confirmEntry.grid(row=3, column=0, padx=5, pady=5)
    
    # متغير لعرض مفتاح الاسترداد الجديد
    newRecoveryKeyVar = tk.StringVar()
    newRecoveryKeyVar.set("")  # سيتم تعبئته بعد التغيير
    
    # تسمية لعرض مفتاح الاسترداد
    recovery_label = tk.Label(
        main_frame, 
        textvariable=newRecoveryKeyVar, 
        font=FONT, 
        wraplength=400,
        bg=DARK_BG,
        fg=SECONDARY_COLOR,
        justify="center"
    )
    recovery_label.pack(pady=15)
    
    status_label = tk.Label(
        main_frame, 
        text="", 
        font=FONT,
        bg=DARK_BG,
        fg=WARNING_COLOR
    )
    status_label.pack(pady=10)
    
    button_frame = tk.Frame(main_frame, bg=DARK_BG)
    button_frame.pack(pady=15)
    
    def changePassword():
        pw = pwEntry.get()
        confirm = confirmEntry.get()
        
        if not pw or not confirm:
            status_label.config(text="Please fill both fields")
            return
            
        if pw != confirm:
            status_label.config(text="Passwords do not match")
            return

        # إنشاء مفاتيح جديدة
        hashedPassword = hashPassword(pw)
        masterKey = secrets.token_urlsafe(32)
        encryptedMasterKey = encrypt(
            masterKey.encode(), base64.urlsafe_b64encode(kdf(pw))
        )
        recoveryKey = secrets.token_urlsafe(32).lower()
        encryptedRecoveryKey = encrypt(
            masterKey.encode(), base64.urlsafe_b64encode(kdf(recoveryKey))
        )
        hashedRecoveryKey = hashPassword(recoveryKey)

        # إعادة تشفير بيانات القبو إذا كان هناك مفتاح قديم
        if "old_encryptionKey" in current_user:
            cursor.execute("SELECT * FROM vault WHERE user_id = ?", (current_user["id"],))
            entries = cursor.fetchall()
            
            for entry in entries:
                try:
                    # فك تشفير باستخدام المفتاح القديم
                    website = decrypt(entry[2], current_user["old_encryptionKey"])
                    username = decrypt(entry[3], current_user["old_encryptionKey"])
                    password_val = decrypt(entry[4], current_user["old_encryptionKey"])
                    
                    # تشفير باستخدام المفتاح الجديد
                    new_key = base64.urlsafe_b64encode(kdf(masterKey))
                    w_enc = encrypt(website, new_key)
                    u_enc = encrypt(username, new_key)
                    p_enc = encrypt(password_val, new_key)
                    
                    # تحديث السجل في قاعدة البيانات
                    cursor.execute(
                        "UPDATE vault SET website=?, username=?, password=? WHERE id=?",
                        (w_enc, u_enc, p_enc, entry[0])
                    )
                except Exception as e:
                    print(f"Error re-encrypting entry {entry[0]}: {e}")

        # تحديث بيانات المستخدم
        cursor.execute(
            """
            UPDATE users SET password=?, masterKeyEncrypted=?, recoveryKey=?, recoveryKeyEncrypted=?
            WHERE id=?
            """,
            (
                hashedPassword,
                encryptedMasterKey,
                hashedRecoveryKey,
                encryptedRecoveryKey,
                current_user["id"],
            ),
        )
        db.commit()

        # تحديث مفتاح التشفير الحالي
        current_user["encryptionKey"] = base64.urlsafe_b64encode(kdf(masterKey))
        
        # تنظيف المفتاح القديم
        if "old_encryptionKey" in current_user:
            del current_user["old_encryptionKey"]
        if "temp_recovery_key" in current_user:
            del current_user["temp_recovery_key"]
        
        # عرض مفتاح الاسترداد الجديد
        newRecoveryKeyVar.set(
            f"New Recovery Key: {recoveryKey}\n\nIMPORTANT: Save this key in a safe place!"
        )
        status_label.config(
            text="Password changed successfully!",
            fg=SUCCESS_COLOR
        )
        # تفعيل زر النسخ
        copy_button.config(state="normal")
        
        # تعطيل حقول الإدخال بعد النجاح
        pwEntry.config(state="disabled")
        confirmEntry.config(state="disabled")
        btnChange.config(state="disabled")
        
        log_activity("Password changed successfully")
    
    btnChange = create_rounded_button(
        button_frame, 
        "Change Password", 
        changePassword, 
        bg=ACCENT_COLOR
    )
    btnChange.pack(side="left", padx=10)
    
    # زر نسخ مفتاح الاسترداد الجديد
    def copyNewRecoveryKey():
        clipboard.copy(newRecoveryKeyVar.get().split(": ")[1].split("\n")[0])
        messagebox.showinfo("Copied", "New recovery key copied to clipboard!")
        log_activity("Copied new recovery key to clipboard")
    
    copy_button = create_rounded_button(
        button_frame, 
        "Copy New Key", 
        copyNewRecoveryKey, 
        bg=SECONDARY_COLOR,
        state="disabled"  # سيتم تفعيله بعد التغيير
    )
    copy_button.pack(side="left", padx=10)
    
    # زر للعودة إلى شاشة الدخول
    def backToLogin():
        loginScreen()
        log_activity("Returned to login screen from password change")
    
    back_button = create_rounded_button(
        button_frame, 
        "Back to Login", 
        backToLogin,
        bg=WARNING_COLOR
    )
    back_button.pack(side="left", padx=10)
    
    apply_dark_theme(main_frame)

# شاشة تسجيل الدخول
def loginScreen():
    log_activity("Accessed login screen")
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("500x400")
    window.title(f"{APP_NAME} - Login")
    
    main_frame = tk.Frame(window, bg=DARK_BG)
    main_frame.pack(fill="both", expand=True, padx=30, pady=30)
    
    title = tk.Label(
        main_frame, 
        text=APP_NAME, 
        font=HEADER_FONT,
        bg=DARK_BG,
        fg=ACCENT_COLOR
    )
    title.pack(pady=20)
    
    form_frame = tk.Frame(main_frame, bg=DARK_BG)
    form_frame.pack(pady=15)
    
    tk.Label(
        form_frame, 
        text="Username", 
        bg=DARK_BG, 
        fg=DARK_FG,
        font=FONT
    ).grid(row=0, column=0, sticky="w", padx=5, pady=5)
    usernameEntry = tk.Entry(form_frame, width=25, font=FONT)
    usernameEntry.grid(row=1, column=0, padx=5, pady=5)
    
    tk.Label(
        form_frame, 
        text="Password", 
        bg=DARK_BG, 
        fg=DARK_FG,
        font=FONT
    ).grid(row=2, column=0, sticky="w", padx=5, pady=10)
    passwordEntry = tk.Entry(form_frame, width=25, show="*", font=FONT)
    passwordEntry.grid(row=3, column=0, padx=5, pady=5)
    
    status_label = tk.Label(
        main_frame, 
        text="", 
        font=FONT,
        bg=DARK_BG,
        fg=WARNING_COLOR
    )
    status_label.pack(pady=10)
    
    button_frame = tk.Frame(main_frame, bg=DARK_BG)
    button_frame.pack(pady=15)
    
    def checkLogin():
        username = usernameEntry.get().strip()
        pw = passwordEntry.get()

        if not username or not pw:
            status_label.config(text="Please enter username and password")
            return

        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if not user or hashPassword(pw) != user[2]:
            status_label.config(text="Invalid username or password")
            log_activity(f"Failed login attempt for user: {username}")
            return

        try:
            key = base64.urlsafe_b64encode(kdf(pw))
            masterKey = decrypt(user[4], key).decode()
            current_user["id"] = user[0]
            
            # تخزين المفتاح القديم في حالة تغيير كلمة المرور
            current_user["old_encryptionKey"] = base64.urlsafe_b64encode(kdf(masterKey))
            
            current_user["encryptionKey"] = base64.urlsafe_b64encode(kdf(masterKey))

            log_activity(f"Login successful for user: {username}")
            show_mfa_screen(username, user[0])
        except:
            status_label.config(text="Failed to decrypt master key")
            log_activity(f"Login failed for user: {username} (decryption error)")
    
    btnLogin = create_rounded_button(
        button_frame, 
        "Login", 
        checkLogin, 
        bg=ACCENT_COLOR
    )
    btnLogin.pack(side="left", padx=10)
    
    btnRegister = create_rounded_button(
        button_frame, 
        "Register", 
        registerScreen
    )
    btnRegister.pack(side="left", padx=10)
    
    btnReset = create_rounded_button(
        button_frame, 
        "Forgot Password?", 
        resetScreen,
        bg=WARNING_COLOR
    )
    btnReset.pack(side="left", padx=10)
    
    apply_dark_theme(main_frame)

# شاشة إدارة كلمات المرور (Vault)
def vaultScreen():
    log_activity("Accessed password vault")
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("900x700")
    window.title(f"{APP_NAME} - Password Vault")
    
    main_frame = tk.Frame(window, bg=DARK_BG)
    main_frame.pack(fill="both", expand=True, padx=20, pady=20)
    
    header_frame = tk.Frame(main_frame, bg=DARK_BG)
    header_frame.pack(fill="x", pady=10)
    
    title = tk.Label(
        header_frame, 
        text="Password Vault", 
        font=HEADER_FONT,
        bg=DARK_BG,
        fg=ACCENT_COLOR
    )
    title.pack(side="left", padx=10)
    
    # أزرار التحكم
    control_frame = tk.Frame(header_frame, bg=DARK_BG)
    control_frame.pack(side="right", padx=10)
    
    # زر إنشاء كلمات مرور
    btnGenerate = create_rounded_button(
        control_frame, 
        "Generate Password", 
        show_password_generator,
        bg=GENERATE_COLOR,
        fg=DARK_BG
    )
    btnGenerate.pack(side="left", padx=8)
    
    btnAddNew = create_rounded_button(
        control_frame, 
        "Add New", 
        addEntry,
        bg=SECONDARY_COLOR,
        fg=DARK_BG
    )
    btnAddNew.pack(side="left", padx=8)
    
    btnLogout = create_rounded_button(
        control_frame, 
        "Logout", 
        logout,
        bg=WARNING_COLOR
    )
    btnLogout.pack(side="left", padx=8)
    
    # جدول كلمات المرور
    table_frame = tk.Frame(main_frame, bg=DARK_BG)
    table_frame.pack(fill="both", expand=True, pady=15)

    # تعريف دالة تبديل كلمة المرور خارج الحلقة
    def toggle_password(label, pwd):
        if label.cget("text") == "••••••••":
            label.config(text=pwd)
        else:
            label.config(text="••••••••")
    
    # عناوين الجدول
    headers = ["Website", "Username", "Password", "Actions"]
    for col, header in enumerate(headers):
        lbl = tk.Label(
            table_frame, 
            text=header, 
            font=("Segoe UI", 12, "bold"),
            bg=ACCENT_COLOR,
            fg=DARK_FG,
            padx=15,
            pady=10
        )
        lbl.grid(row=0, column=col, sticky="nsew", padx=1, pady=1)
    
    # بيانات الجدول
    cursor.execute("SELECT * FROM vault WHERE user_id = ?", (current_user["id"],))
    entries = cursor.fetchall()
    
    if not entries:
        empty_label = tk.Label(
            table_frame, 
            text="No passwords stored yet. Click 'Add New' to get started.",
            font=("Segoe UI", 12),
            bg=DARK_BG,
            fg=DARK_FG,
            pady=30
        )
        empty_label.grid(row=1, column=0, columnspan=4)
    else:
        for row, entry in enumerate(entries, start=1):
            try:
                website = decrypt(entry[2], current_user["encryptionKey"]).decode()
                username = decrypt(entry[3], current_user["encryptionKey"]).decode()
                password = decrypt(entry[4], current_user["encryptionKey"]).decode()
            except:
                website = "Decryption Error"
                username = "Decryption Error"
                password = "Decryption Error"
            
            # عرض بيانات الموقع
            tk.Label(
                table_frame, 
                text=website, 
                font=FONT,
                bg=ENTRY_BG,
                fg=DARK_FG,
                padx=15,
                pady=10
            ).grid(row=row, column=0, sticky="nsew", padx=1, pady=1)
            
            # عرض اسم المستخدم
            tk.Label(
                table_frame, 
                text=username, 
                font=FONT,
                bg=ENTRY_BG,
                fg=DARK_FG,
                padx=15,
                pady=10
            ).grid(row=row, column=1, sticky="nsew", padx=1, pady=1)
            
            # إطار كلمة المرور مع زر الإظهار
            password_frame = tk.Frame(table_frame, bg=ENTRY_BG)
            password_frame.grid(row=row, column=2, sticky="nsew", padx=1, pady=1)
            
            # تسمية كلمة المرور (مخفية)
            password_label = tk.Label(
                password_frame, 
                text="••••••••", 
                font=FONT,
                bg=ENTRY_BG,
                fg=DARK_FG,
                padx=15,
                pady=10
            )
            password_label.pack(side="left", expand=True)
            
            # زر إظهار/إخفاء كلمة المرور
            show_btn = tk.Button(
                password_frame, 
                text="Show", 
                command=lambda lbl=password_label, pwd=password: toggle_password(lbl, pwd),
                bg=BUTTON_BG,
                fg=DARK_FG,
                padx=8,
                pady=4,
                font=("Segoe UI", 9)
            )
            show_btn.pack(side="right", padx=10)
            
            # إطار أزرار الإجراءات
            action_frame = tk.Frame(table_frame, bg=ENTRY_BG)
            action_frame.grid(row=row, column=3, sticky="nsew", padx=1, pady=1)
            
            # توزيع الأزرار مع تباعد
            action_btn_frame = tk.Frame(action_frame, bg=ENTRY_BG)
            action_btn_frame.pack(pady=10, padx=10)
            
            update_btn = tk.Button(
                action_btn_frame, 
                text="Update", 
                command=partial(updateEntry, entry[0]),
                bg="#FFA500",
                fg=DARK_BG,
                padx=8,
                pady=4,
                font=("Segoe UI", 9)
            )
            update_btn.pack(side="left", padx=5)
            
            delete_btn = tk.Button(
                action_btn_frame, 
                text="Delete", 
                command=partial(removeEntry, entry[0]),
                bg=WARNING_COLOR,
                fg=DARK_BG,
                padx=8,
                pady=4,
                font=("Segoe UI", 9)
            )
            delete_btn.pack(side="left", padx=5)
            
            # زر نسخ كلمة المرور
            def copy_password(site, pwd):
                clipboard.copy(pwd)
                messagebox.showinfo("Copied", "Password copied to clipboard!")
                log_activity(f"Copied password for {site}")
            
            copy_btn = tk.Button(
                action_btn_frame, 
                text="Copy", 
                command=lambda site=website, pwd=password: copy_password(site, pwd),
                bg="#4CAF50",
                fg=DARK_BG,
                padx=8,
                pady=4,
                font=("Segoe UI", 9)
            )
            copy_btn.pack(side="left", padx=5)

def addEntry():
    log_activity("Initiating new password entry creation")
    try:
        website = simpledialog.askstring("Add Entry", "Website:")
        if not website or not website.strip():
            log_activity("Canceled adding new entry (website missing)")
            return
            
        username = simpledialog.askstring("Add Entry", "Username:")
        if not username or not username.strip():
            log_activity("Canceled adding new entry (username missing)")
            return
            
        password = simpledialog.askstring("Add Entry", "Password:", show="*")
        if not password or not password.strip():
            log_activity("Canceled adding new entry (password missing)")
            return

        # التشفير باستخدام المفتاح الصحيح
        w_enc = encrypt(website.encode(), current_user["encryptionKey"])
        u_enc = encrypt(username.encode(), current_user["encryptionKey"])
        p_enc = encrypt(password.encode(), current_user["encryptionKey"])

        cursor.execute(
            "INSERT INTO vault (user_id, website, username, password) VALUES (?, ?, ?, ?)",
            (current_user["id"], w_enc, u_enc, p_enc)
        )
        db.commit()
        log_activity(f"Added new entry for {website}")
        vaultScreen()  # تحديث الواجهة
    except Exception as e:
        messagebox.showerror("Error", f"Failed to add entry: {str(e)}")
        log_activity(f"Failed to add new entry: {str(e)}")

def removeEntry(entry_id):
    if messagebox.askyesno("Confirm", "Are you sure you want to delete this entry?"):
        try:
            cursor.execute("SELECT website FROM vault WHERE id = ?", (entry_id,))
            website = cursor.fetchone()[0]
            cursor.execute("DELETE FROM vault WHERE id = ?", (entry_id,))
            db.commit()
            log_activity(f"Removed entry for {website}")
            vaultScreen()
        except:
            log_activity("Failed to remove entry")
            messagebox.showerror("Error", "Failed to delete entry")

def updateEntry(entry_id):
    try:
        cursor.execute("SELECT website FROM vault WHERE id = ?", (entry_id,))
        website = cursor.fetchone()[0]
        
        new_password = simpledialog.askstring("Update Password", "Enter new password:", show="*")
        if not new_password or not new_password.strip():
            log_activity("Canceled password update")
            return
            
        try:
            p_enc = encrypt(new_password.encode(), current_user["encryptionKey"])
            cursor.execute("UPDATE vault SET password = ? WHERE id = ?", (p_enc, entry_id))
            db.commit()
            log_activity(f"Updated password for {website}")
            vaultScreen()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to update password: {str(e)}")
            log_activity(f"Failed to update password for {website}: {str(e)}")
    except:
        log_activity("Failed to update password (entry not found)")
        messagebox.showerror("Error", "Entry not found")

def logout():
    log_activity("User logged out")
    global current_user
    current_user = {"id": None, "encryptionKey": None, "old_encryptionKey": None}
    loginScreen()

# --- بدء التطبيق ---
window = tk.Tk()
window.title(APP_NAME)
window.geometry("500x400")
window.configure(bg=DARK_BG)

# التحقق من وجود مستخدمين
cursor.execute("SELECT * FROM users")
if cursor.fetchone():
    loginScreen()
else:
    registerScreen()

window.mainloop()