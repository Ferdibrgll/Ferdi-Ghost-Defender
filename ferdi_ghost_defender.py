import os
import sys
import socket
import psutil
import random
import time
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QWidget, QPushButton, QVBoxLayout, QLabel,
    QTextEdit, QHBoxLayout, QFileDialog, QDialog, QListWidget,
    QDialogButtonBox, QAbstractItemView, QLineEdit, QMessageBox
)
from PyQt5.QtGui import QFont, QTextCursor
from PyQt5.QtCore import Qt, QTimer

try:
    from Crypto.Cipher import AES
except ImportError:
    print("PyCryptoDome not found. Install via: pip3 install pycryptodome")

# ------------------- Signatures -------------------
SIGNATURES = {
    "RAT": [b"socket.connect", b"com.rat", b"reverse_shell"],
    "BACKDOOR": [b"/dev/tcp/", b"bash -i", b"nohup"],
    "VIRUS": [b"mov eax", b"jmp", b"xor"],
    "MALWARE": [b"keylogger", b"chmod 777", b"rm -rf", b"wget http"]
}

# ------------------- ASCII Banner -------------------
BANNER_ASCII = r"""
███████╗███████╗██████╗ ███████╗██████╗ ██╗███████╗██████╗ 
██╔════╝██╔════╝██╔══██╗██╔════╝██╔══██╗██║██╔════╝██╔══██╗
███████╗█████╗  ██████╔╝█████╗  ██████╔╝██║█████╗  ██████╔╝
╚════██║██╔══╝  ██╔══██╗██╔══╝  ██╔═══╝ ██║██╔══╝  ██╔══██╗
███████║███████╗██║  ██║███████╗██║     ██║███████╗██║  ██║
╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝
"""

HEADER_ASCII = "FERDI GHOST DEFENDER - ULTRA HACKER MODE\n"

# ------------------- Logging -------------------
LOG_FILE = "ferdi_ultimate_log.txt"

def log_event(event):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.now()} | {event}\n")

# ------------------- Scan Functions -------------------
def scan_file(path):
    try:
        with open(path, "rb") as f:
            data = f.read()
            for family, sigs in SIGNATURES.items():
                for sig in sigs:
                    if sig in data:
                        log_event(f"[ALERT: {family}] {path}")
                        return (f"[ALERT: {family}] {path}", family)
        return (f"[CLEAN] {path}", None)
    except Exception as e:
        return (f"[ERROR] {path}: {str(e)}", None)

def scan_directory(path):
    results = []
    for root, _, files in os.walk(path):
        for name in files:
            fpath = os.path.join(root, name)
            results.append(scan_file(fpath))
    return results

# ------------------- Threat Dialog -------------------
class ThreatDialog(QDialog):
    def __init__(self, threats, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Threats Detected")
        self.setFixedSize(600, 400)
        self.setStyleSheet("background-color: #111; color: #00ff66;")
        self.selected_option = None

        layout = QVBoxLayout()
        self.list_widget = QListWidget()
        self.list_widget.addItems(threats)
        self.list_widget.setSelectionMode(QAbstractItemView.NoSelection)
        layout.addWidget(self.list_widget)

        buttons = QDialogButtonBox()
        self.all_btn = QPushButton("Delete All")
        self.skip_btn = QPushButton("Skip All")
        self.manual_btn = QPushButton("Delete One-by-One")
        for btn in [self.all_btn, self.skip_btn, self.manual_btn]:
            buttons.addButton(btn, QDialogButtonBox.ActionRole)
        self.all_btn.clicked.connect(lambda: self.finish("all"))
        self.skip_btn.clicked.connect(lambda: self.finish("skip"))
        self.manual_btn.clicked.connect(lambda: self.finish("manual"))
        layout.addWidget(buttons)
        self.setLayout(layout)

    def finish(self, choice):
        self.selected_option = choice
        self.accept()

# ------------------- Ferdi Ghost GUI -------------------
class FerdiGhost(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("FERDI GHOST ULTIMATE DEFENDER")
        self.setFixedSize(1200, 800)
        self.setStyleSheet("background-color: black; color: #00ff66;")
        self.setFont(QFont("Courier New", 10))
        self.detected_files = []

        layout = QVBoxLayout()
        self.banner = QLabel(BANNER_ASCII)
        self.banner.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.banner)

        self.header = QLabel(HEADER_ASCII)
        self.header.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.header)

        self.output = QTextEdit()
        self.output.setReadOnly(True)
        layout.addWidget(self.output)

        # Buttons
        btns = QHBoxLayout()
        self.file_btn = QPushButton("Scan File")
        self.folder_btn = QPushButton("Scan Folder")
        self.proc_btn = QPushButton("Process Scan")
        self.net_btn = QPushButton("Network Scan")
        self.fake_btn = QPushButton("Fake Exploit Logs")
        self.encrypt_btn = QPushButton("Encrypt File")
        self.decrypt_btn = QPushButton("Decrypt File")
        self.kill_proc_btn = QPushButton("Kill Process")
        self.matrix_btn = QPushButton("Matrix Effect")
        self.export_btn = QPushButton("Export Logs")
        for btn in [self.file_btn, self.folder_btn, self.proc_btn, self.net_btn, self.fake_btn]:
            btns.addWidget(btn)
        layout.addLayout(btns)

        self.file_btn.clicked.connect(self.scan_file_action)
        self.folder_btn.clicked.connect(self.scan_folder_action)
        self.proc_btn.clicked.connect(self.process_scan)
        self.net_btn.clicked.connect(self.network_scan)
        self.fake_btn.clicked.connect(self.fake_exploit_logs)
        self.encrypt_btn.clicked.connect(self.encrypt_file_action)
        self.decrypt_btn.clicked.connect(self.decrypt_file_action)
        self.kill_proc_btn.clicked.connect(self.kill_process_action)
        self.matrix_btn.clicked.connect(lambda: matrix_effect(self.output))
        self.export_btn.clicked.connect(export_logs_csv)
        self.setLayout(layout)
        self.typing_text = ">> Ferdi Ghost Ultimate Defender Activated...\n"
        self.typing_index = 0
        self.timer = QTimer()
        self.timer.timeout.connect(self.animate_typing)
        self.timer.start(30)

    # Typing animation
    def animate_typing(self):
        if self.typing_index < len(self.typing_text):
            self.output.moveCursor(QTextCursor.End)
            self.output.insertPlainText(self.typing_text[self.typing_index])
            self.typing_index += 1
        else:
            self.timer.stop()

    # ------------------- File Scan -------------------
    def scan_file_action(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if path:
            result, family = scan_file(path)
            self.output.append(result)

    def scan_folder_action(self):
        path = QFileDialog.getExistingDirectory(self, "Select Folder")
        if path:
            results = scan_directory(path)
            for res, family in results:
                self.output.append(res)

    # ------------------- Process Scan -------------------
    def process_scan(self):
        self.output.append(">> Scanning Running Processes...")
        for proc in psutil.process_iter(['pid','name']):
            try:
                self.output.append(f"{proc.info['pid']:>5} | {proc.info['name']}")
            except:
                continue

    # ------------------- Network Scan -------------------
    def network_scan(self):
        self.output.append(">> Performing Network Scan...")
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        self.output.append(f"Local Host: {hostname} ({ip})")
        for port in range(20, 105):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.05)
            try:
                s.connect((ip, port))
                self.output.append(f"[OPEN] Port {port}")
            except:
                pass
            s.close()

    # ------------------- Fake Exploit -------------------
    def fake_exploit_logs(self):
        self.output.append(">> Initiating Fake Exploit Sequence...")
        exploits = ["Reverse Shell Attempt", "SQLi Detected", "Buffer Overflow Triggered", "Keylogger Installed"]
        for i in range(15):
            log = random.choice(exploits)
            self.output.append(f"[{datetime.now()}] {log} on 192.168.{random.randint(0,255)}.{random.randint(0,255)}")
            QTimer.singleShot(i*200, lambda: None)  # simulate delay

# ------------------- Run -------------------
def run_app():
    os.environ["XDG_RUNTIME_DIR"] = "/tmp/runtime-root"
    app = QApplication(sys.argv)
    window = FerdiGhost()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    run_app()


# Kodun ana yapısı büyük olduğu için burada sadece eklenen özelliklerin örnek implementasyonu:

# ------------------- AES / XOR Encrypt-Decrypter -------------------
def aes_encrypt_file(path, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_EAX)
    with open(path, 'rb') as f:
        data = f.read()
    ciphertext, tag = cipher.encrypt_and_digest(data)
    with open(path + ".enc", 'wb') as f:
        f.write(cipher.nonce + tag + ciphertext)
    return path + ".enc"

def aes_decrypt_file(enc_path, key):
    with open(enc_path, 'rb') as f:
        nonce, tag, ciphertext = f.read()[:16], f.read()[16:32], f.read()[32:]
    cipher = AES.new(key.encode('utf-8'), AES.MODE_EAX, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    out_path = enc_path.replace(".enc", ".dec")
    with open(out_path, 'wb') as f:
        f.write(data)
    return out_path

def xor_encrypt_decrypt(data, key):
    return bytes([b ^ key for b in data])

# ------------------- Process Kill / Autorun -------------------
def kill_process_by_name(name):
    for proc in psutil.process_iter(['name','pid']):
        if proc.info['name'] == name:
            try:
                proc.kill()
                log_event(f"[PROCESS KILLED] {name} ({proc.info['pid']})")
            except:
                pass

def scan_autorun():
    autoruns = []
    if platform.system() == "Windows":
        import winreg
        path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_READ)
        for i in range(0, winreg.QueryInfoKey(key)[1]):
            name, value, _ = winreg.EnumValue(key, i)
            autoruns.append((name, value))
    return autoruns

# ------------------- Log Export -------------------
def export_logs_csv():
    import csv
    with open(LOG_FILE, "r") as f:
        lines = f.readlines()
    with open("ferdi_log.csv", "w", newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp", "Event"])
        for line in lines:
            if "|" in line:
                ts, ev = line.split("|",1)
                writer.writerow([ts.strip(), ev.strip()])

# ------------------- Matrix Neon Output -------------------
def matrix_effect(output_widget):
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
    for _ in range(100):
        line = "".join(random.choice(chars) for _ in range(80))
        output_widget.append(line)
        QApplication.processEvents()
        time.sleep(0.02)
