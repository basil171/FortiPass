import re
import random
import time
import os
from datetime import datetime
from colorama import Fore, Style, init

# تفعيل الألوان
init(autoreset=True)

# ملفات المشروع
LOGS_DIR = "logs"
REPORT_FILE = os.path.join(LOGS_DIR, "report.txt")
ACCOUNTS_FILE = "accounts.txt"

# إنشاء فولدر logs لو مش موجود
if not os.path.exists(LOGS_DIR):
    os.makedirs(LOGS_DIR)

# ============ Logging ============
def log_result(category, message):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(REPORT_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{now}] [{category}] {message}\n")

def show_report():
    print(Fore.CYAN + "\n📑 Final Report:\n" + "-"*50)
    try:
        with open(REPORT_FILE, "r", encoding="utf-8") as f:
            print(f.read())
    except FileNotFoundError:
        print(Fore.YELLOW + "⚠️ No report found.")

# ============ Banner ============
def banner():
    print(Fore.MAGENTA + Style.BRIGHT + r"""
███████╗ ██████╗ ██████╗ ████████╗██╗██████╗  █████╗ ███████╗███████╗
██╔════╝██╔═══██╗██╔══██╗╚══██╔══╝██║██╔══██╗██╔══██╗██╔════╝██╔════╝
█████╗  ██║   ██║██████╔╝   ██║   ██║██████╔╝███████║███████╗█████╗  
██╔══╝  ██║   ██║██╔═══╝    ██║   ██║██╔═══╝ ██╔══██║╚════██║██╔══╝  
██║     ╚██████╔╝██║        ██║   ██║██║     ██║  ██║███████║███████╗
╚═╝      ╚═════╝ ╚═╝        ╚═╝   ╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝
                       FortiPass Security Toolkit
    """)

# ============ 1. Password Strength Checker ============
def check_password_strength(password):
    length_error = len(password) < 8
    digit_error = re.search(r"\\d", password) is None
    uppercase_error = re.search(r"[A-Z]", password) is None
    lowercase_error = re.search(r"[a-z]", password) is None
    symbol_error = re.search(r"[@$!%*?&]", password) is None

    errors = [length_error, digit_error, uppercase_error, lowercase_error, symbol_error]

    if all(not e for e in errors):
        msg = f"✅ Strong password: {password}"
        log_result("Strength", msg)
        return Fore.GREEN + msg
    else:
        msg = f"❌ Weak password: {password}"
        log_result("Strength", msg)
        return Fore.RED + msg

# ============ 2. Password Leak Checker (Wordlist) ============
def check_password_leak(password, wordlist_file):
    try:
        with open(wordlist_file, "r", encoding="utf-8", errors="ignore") as f:
            leaked_passwords = set(line.strip() for line in f)
        if password in leaked_passwords:
            msg = f"⚠️ Password found in leaks: {password}"
            log_result("Leak", msg)
            return Fore.RED + msg
        else:
            msg = "✅ Password not found in leaks."
            log_result("Leak", msg)
            return Fore.GREEN + msg
    except FileNotFoundError:
        return Fore.YELLOW + "⚠️ Wordlist not found!"

# ============ 3. Email Leak Checker ============
def check_email_leak(email, wordlist_file):
    try:
        with open(wordlist_file, "r", encoding="utf-8", errors="ignore") as f:
            leaked_emails = set(line.strip() for line in f)
        if email in leaked_emails:
            msg = f"⚠️ Email found in leaks: {email}"
            log_result("Email", msg)
            return Fore.RED + msg
        else:
            msg = "✅ Email not found in leaks."
            log_result("Email", msg)
            return Fore.GREEN + msg
    except FileNotFoundError:
        return Fore.YELLOW + "⚠️ Wordlist not found!"

# ============ 4. Password Generator ============
def generate_password(length=12):
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@$!%*?&"
    password = "".join(random.choice(chars) for _ in range(length))
    msg = f"🔑 Generated password: {password}"
    log_result("Generator", msg)
    return Fore.CYAN + msg

# ============ 5. Early Warning System ============
def monitor_email(email, wordlist_file):
    print(Fore.CYAN + f"🔍 Monitoring email: {email}")
    time.sleep(2)
    return check_email_leak(email, wordlist_file)

# ============ 6. Password Reuse Detector ============
def add_account(email, password):
    with open(ACCOUNTS_FILE, "a", encoding="utf-8") as f:
        f.write(f"{email}:{password}\n")
    msg = f"✅ Account added: {email}"
    log_result("Accounts", msg)
    print(Fore.GREEN + msg)

def load_accounts():
    try:
        with open(ACCOUNTS_FILE, "r", encoding="utf-8") as f:
            accounts = {}
            for line in f:
                if ":" in line:
                    email, pwd = line.strip().split(":", 1)
                    accounts[email] = pwd
            return accounts
    except FileNotFoundError:
        return {}

def run_password_reuse_detector():
    accounts = load_accounts()
    if not accounts:
        print(Fore.YELLOW + "⚠️ No accounts found! Add some first.")
        return

    print(Fore.CYAN + "\n🔍 Checking password reuse...")
    reverse_map = {}
    for email, pwd in accounts.items():
        reverse_map.setdefault(pwd, []).append(email)

    found = False
    for pwd, emails in reverse_map.items():
        if len(emails) > 1:
            msg = f"⚠️ Password reused for: {', '.join(emails)}"
            log_result("Password Reuse", msg)
            print(Fore.RED + msg)
            found = True

    if not found:
        msg = "✅ No password reuse detected."
        log_result("Password Reuse", msg)
        print(Fore.GREEN + msg)

# ============ Main ============
def main():
    banner()
    while True:
        print(Fore.YELLOW + "\nChoose an option:")
        print("1. Check Password Strength")
        print("2. Check Password Leak (Wordlist)")
        print("3. Check Email Leak (Wordlist)")
        print("4. Generate Strong Password")
        print("5. Monitor Email (Early Warning)")
        print("6. Run Password Reuse Detector")
        print("7. Add Account (Email + Password)")
        print("8. Show Final Report")
        print("9. Exit")

        choice = input(Fore.CYAN + "Enter choice: ")

        if choice == "1":
            pwd = input("Enter password: ")
            print(check_password_strength(pwd))
        elif choice == "2":
            pwd = input("Enter password: ")
            wl = input("Enter wordlist path: ")
            print(check_password_leak(pwd, wl))
        elif choice == "3":
            email = input("Enter email: ")
            wl = input("Enter wordlist path: ")
            print(check_email_leak(email, wl))
        elif choice == "4":
            length = int(input("Enter length: "))
            print(generate_password(length))
        elif choice == "5":
            email = input("Enter email: ")
            wl = input("Enter wordlist path: ")
            print(monitor_email(email, wl))
        elif choice == "6":
            run_password_reuse_detector()
        elif choice == "7":
            email = input("Enter email: ")
            pwd = input("Enter password: ")
            add_account(email, pwd)
        elif choice == "8":
            show_report()
        elif choice == "9":
            print(Fore.MAGENTA + "Goodbye! Stay safe with FortiPass 🔐")
            show_report()
            break
        else:
            print(Fore.RED + "❌ Invalid choice!")

if __name__ == "__main__":
    main()
