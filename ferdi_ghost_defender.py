import os
import sys
import webbrowser
import psutil
import socket
import platform
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QWidget, QPushButton, QVBoxLayout, QLabel,
    QFileDialog, QTextEdit, QHBoxLayout, QMessageBox, QDialog, QListWidget,
    QDialogButtonBox, QAbstractItemView
)
from PyQt5.QtGui import QFont, QTextCursor
from PyQt5.QtCore import Qt, QTimer

try:
    from Crypto.Cipher import AES
except ImportError:
    print("PyCryptoDome not found. Install via: pip3 install pycryptodome")

# ------------------- Signature definitions -------------------
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

# ------------------- Header -------------------
HEADER_ASCII = r"""
FERDI GHOST DEFENDER - HACKER/AGENT MODE
"""

LINKS = {
    "YouTube": "https://www.youtube.com/@Ferdibirgul",
    "Instagram": "https://instagram.com/ferdibirgull",
    "TikTok": "https://tiktok.com/@ferdibirgull",
    "GitHub": "https://github.com/ferdibrgll",
    "Blog": "https://ferdiblog.com",
    "Linktree": "https://linktr.ee/ferdibirgll"
}

# ------------------- File Scan -------------------
def scan_file(path):
    try:
        with open(path, "rb") as f:
            data = f.read()
            for family, sigs in SIGNATURES.items():
                for sig in sigs:
                    if sig in data:
                        log_threat(path, family)
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

# ------------------- Log -------------------
def log_threat(path, family):
    with open("ferdi_log.txt", "a") as f:
        f.write(f"{datetime.now()} | [{family}] {path}\n")

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
        self.list_widget.setStyleSheet("background-color: black; color: #00ff66;")
        layout.addWidget(self.list_widget)

        buttons = QDialogButtonBox()
        self.all_btn = QPushButton("Delete All")
        self.skip_btn = QPushButton("Skip All")
        self.manual_btn = QPushButton("Delete One-by-One")
        for btn in [self.all_btn, self.skip_btn, self.manual_btn]:
            btn.setStyleSheet("background-color: #222; color: #00ff66; padding: 6px;")
            buttons.addButton(btn, QDialogButtonBox.ActionRole)

        self.all_btn.clicked.connect(lambda: self.finish("all"))
        self.skip_btn.clicked.connect(lambda: self.finish("skip"))
        self.manual_btn.clicked.connect(lambda: self.finish("manual"))
        layout.addWidget(buttons)
        self.setLayout(layout)

    def finish(self, choice):
        self.selected_option = choice
        self.accept()

# ------------------- FerdiGhost GUI -------------------
class FerdiGhost(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ferdi ghost defender")
        self.setFixedSize(1100, 750)
        self.setStyleSheet("background-color: black; color: #00ff66;")
        self.setFont(QFont("Courier New", 10))
        self.detected_files = []

        layout = QVBoxLayout()

        # Banner
        self.banner = QLabel(BANNER_ASCII)
        self.banner.setTextFormat(Qt.PlainText)
        self.banner.setAlignment(Qt.AlignCenter)
        self.banner.setFont(QFont("Courier New", 9))
        layout.addWidget(self.banner)

        # Header
        self.header = QLabel(HEADER_ASCII)
        self.header.setTextFormat(Qt.PlainText)
        self.header.setAlignment(Qt.AlignCenter)
        self.header.setFont(QFont("Courier New", 10))
        layout.addWidget(self.header)

        # Output
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setStyleSheet("background-color: black; border: 1px solid #00ff66; color: #00ff66;")
        layout.addWidget(self.output)

        # Buttons
        btns = QHBoxLayout()
        self.file_btn = QPushButton("Scan File")
        self.folder_btn = QPushButton("Scan Folder")
        self.net_btn = QPushButton("Network Scan")
        self.proc_btn = QPushButton("Process Scan")
        for btn in [self.file_btn, self.folder_btn, self.net_btn, self.proc_btn]:
            btn.setStyleSheet("background-color: #111; color: #00ff66; padding: 5px 10px;")
            btns.addWidget(btn)
        layout.addLayout(btns)

        self.file_btn.clicked.connect(self.scan_file_action)
        self.folder_btn.clicked.connect(self.scan_folder_action)
        self.net_btn.clicked.connect(self.network_scan)
        self.proc_btn.clicked.connect(self.process_scan)

        # Links
        links = QHBoxLayout()
        for name, url in LINKS.items():
            link_btn = QPushButton(name)
            link_btn.setStyleSheet("background-color: #111; color: #00ff66;")
            link_btn.clicked.connect(lambda _, u=url: webbrowser.open(u))
            links.addWidget(link_btn)
        layout.addLayout(links)

        self.setLayout(layout)
        self.typing_text = ">> Ferdi Ghost Defender Activated...\n"
        self.typing_index = 0
        self.timer = QTimer()
        self.timer.timeout.connect(self.animate_typing)
        self.timer.start(45)

    # ------------------- Animasyon -------------------
    def animate_typing(self):
        if self.typing_index < len(self.typing_text):
            self.output.moveCursor(QTextCursor.End)
            self.output.insertPlainText(self.typing_text[self.typing_index])
            self.typing_index += 1
        else:
            self.timer.stop()

    # ------------------- File Scan Actions -------------------
    def scan_file_action(self):
        self.detected_files = []
        path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if path:
            result, family = scan_file(path)
            self.output.append(result)
            if family:
                self.detected_files.append((path, family))
                self.handle_threats()

    def scan_folder_action(self):
        self.detected_files = []
        path = QFileDialog.getExistingDirectory(self, "Select Folder")
        if path:
            results = scan_directory(path)
            for res, family in results:
                self.output.append(res)
                if family:
                    self.detected_files.append((res.split("] ")[1], family))
            if self.detected_files:
                self.handle_threats()

    # ------------------- Network & Process Scan -------------------
    def network_scan(self):
        self.output.append(">> Starting Network Scan...")
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        self.output.append(f"Hostname: {hostname}, IP: {ip}")
        self.output.append("Open Ports (TCP 20-1024):")
        for port in range(20, 1030):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.05)
            try:
                s.connect((ip, port))
                self.output.append(f"[OPEN] Port {port}")
            except:
                pass
            s.close()

    def process_scan(self):
        self.output.append(">> Scanning Running Processes...")
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                self.output.append(f"{proc.info['pid']:>5} | {proc.info['name']}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    # ------------------- Threat Handling -------------------
    def handle_threats(self):
        threat_lines = [f"[{family}] {path}" for path, family in self.detected_files]
        dialog = ThreatDialog(threat_lines, self)
        if dialog.exec_():
            choice = dialog.selected_option
            if choice == "all":
                for path, family in self.detected_files:
                    try:
                        os.remove(path)
                        self.output.append(f"[DELETED] {path}")
                    except Exception as e:
                        self.output.append(f"[ERROR] {path}: {e}")
            elif choice == "manual":
                for path, family in self.detected_files:
                    confirm = QMessageBox.question(
                        self,
                        "Delete?",
                        f"[{family}] {path}\nDelete this file?",
                        QMessageBox.Yes | QMessageBox.No
                    )
                    if confirm == QMessageBox.Yes:
                        try:
                            os.remove(path)
                            self.output.append(f"[DELETED] {path}")
                        except Exception as e:
                            self.output.append(f"[ERROR] {path}: {e}")
            else:
                self.output.append("Skipped all infected files.")

# ------------------- Run App -------------------
def run_app():
    os.environ["XDG_RUNTIME_DIR"] = "/tmp/runtime-root"
    app = QApplication(sys.argv)
    window = FerdiGhost()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    run_app()
