import os
import sys
import webbrowser
import socket
import subprocess
from PyQt5.QtWidgets import (
    QApplication, QWidget, QPushButton, QVBoxLayout, QLabel,
    QFileDialog, QTextEdit, QHBoxLayout, QMessageBox, QDialog, QListWidget,
    QDialogButtonBox, QAbstractItemView
)
from PyQt5.QtGui import QFont, QTextCursor
from PyQt5.QtCore import Qt, QTimer

# --- Malware Signatures ---
SIGNATURES = {
    "RAT": [b"socket.connect", b"com.rat", b"reverse_shell"],
    "BACKDOOR": [b"/dev/tcp/", b"bash -i", b"nohup"],
    "VIRUS": [b"mov eax", b"jmp", b"xor"],
    "MALWARE": [b"keylogger", b"chmod 777", b"rm -rf", b"wget http"]
}

# --- ASCII Banners ---
BANNER_ASCII = r"""
███████╗███████╗██████╗ ███████╗██╗██████╗ ███████╗
██╔════╝██╔════╝██╔══██╗██╔════╝██║██╔══██╗██╔════╝
███████╗█████╗  ██████╔╝█████╗  ██║██████╔╝█████╗  
╚════██║██╔══╝  ██╔═══╝ ██╔══╝  ██║██╔═══╝ ██╔══╝  
███████║███████╗██║     ███████╗██║██║     ███████╗
╚══════╝╚══════╝╚═╝     ╚══════╝╚═╝╚═╝     ╚══════╝
"""

HEADER_ASCII = r"""
███╗   ███╗ █████╗ ███████╗███████╗ ██████╗ ███████╗
████╗ ████║██╔══██╗██╔════╝██╔════╝██╔═══██╗██╔════╝
██╔████╔██║███████║███████╗█████╗  ██║   ██║███████╗
██║╚██╔╝██║██╔══██║╚════██║██╔══╝  ██║   ██║╚════██║
██║ ╚═╝ ██║██║  ██║███████║███████╗╚██████╔╝███████║
╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝ ╚══════╝
"""

# --- Social Media Links ---
LINKS = {
    "YouTube": "https://www.youtube.com/@Ferdibirgul",
    "Instagram": "https://instagram.com/ferdibirgull",
    "TikTok": "https://tiktok.com/@ferdibirgull",
    "GitHub": "https://github.com/ferdib"
}

# --- File Scanning Functions ---
def scan_file(path):
    try:
        with open(path, "rb") as f:
            data = f.read()
            for family, sigs in SIGNATURES.items():
                for sig in sigs:
                    if sig in data:
                        log_threat(f"[INFECTED: {family}] {path}")
                        return (f"[INFECTED: {family}] {path}", family)
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

# --- Threat Logger ---
def log_threat(message):
    with open("threat_log.txt", "a") as log_file:
        log_file.write(message + "\n")

# --- Threat Dialog ---
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
        self.all_btn = QPushButton("Quarantine All")
        self.skip_btn = QPushButton("Skip All")
        self.manual_btn = QPushButton("Quarantine One-by-One")
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

# --- Network Scanner ---
def scan_network():
    devices = []
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    ip_base = ".".join(local_ip.split(".")[:3]) + "."
    for i in range(1, 255):
        ip = ip_base + str(i)
        try:
            socket.setdefaulttimeout(0.1)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, 80))
            devices.append(ip)
            s.close()
        except:
            continue
    return devices

# --- Main App ---
class FerdiGhost(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("FERDI GHOST 2.0")
        self.setFixedSize(1000, 720)
        self.setStyleSheet("background-color: black; color: #00ff66;")
        self.setFont(QFont("Courier New", 10))
        self.detected_files = []

        layout = QVBoxLayout()

        self.banner = QLabel(BANNER_ASCII)
        self.banner.setTextFormat(Qt.PlainText)
        self.banner.setAlignment(Qt.AlignCenter)
        self.banner.setFont(QFont("Courier New", 9))
        layout.addWidget(self.banner)

        self.header = QLabel(HEADER_ASCII)
        self.header.setTextFormat(Qt.PlainText)
        self.header.setAlignment(Qt.AlignCenter)
        self.header.setFont(QFont("Courier New", 10))
        layout.addWidget(self.header)

        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setStyleSheet("background-color: black; border: 1px solid #00ff66; color: #00ff66;")
        layout.addWidget(self.output)

        # --- Scan Buttons ---
        btns = QHBoxLayout()
        self.file_btn = QPushButton("Scan File")
        self.folder_btn = QPushButton("Scan Folder")
        self.network_btn = QPushButton("Network Scan")
        self.file_btn.clicked.connect(self.scan_file_action)
        self.folder_btn.clicked.connect(self.scan_folder_action)
        self.network_btn.clicked.connect(self.network_scan_action)
        for btn in (self.file_btn, self.folder_btn, self.network_btn):
            btn.setStyleSheet("background-color: #111; color: #00ff66; padding: 5px 10px;")
            btns.addWidget(btn)
        layout.addLayout(btns)

        # --- Social Links ---
        links = QHBoxLayout()
        for name, url in LINKS.items():
            link_btn = QPushButton(name)
            link_btn.setStyleSheet("background-color: #111; color: #00ff66;")
            link_btn.clicked.connect(lambda _, u=url: webbrowser.open(u))
            links.addWidget(link_btn)
        layout.addLayout(links)

        self.setLayout(layout)

        # --- Typing Effect ---
        self.typing_text = ">> Ferdi Ghost Defender 2.0 Activated...\n"
        self.typing_index = 0
        self.timer = QTimer()
        self.timer.timeout.connect(self.animate_typing)
        self.timer.start(45)

    def animate_typing(self):
        if self.typing_index < len(self.typing_text):
            self.output.moveCursor(QTextCursor.End)
            self.output.insertPlainText(self.typing_text[self.typing_index])
            self.typing_index += 1
        else:
            self.timer.stop()

    # --- Scan Actions ---
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

    def handle_threats(self):
        threat_lines = [f"[{family}] {path}" for path, family in self.detected_files]
        dialog = ThreatDialog(threat_lines, self)
        if dialog.exec_():
            choice = dialog.selected_option
            if choice == "all":
                for path, family in self.detected_files:
                    try:
                        os.remove(path)
                        self.output.append(f"[QUARANTINED] {path}")
                    except Exception as e:
                        self.output.append(f"[ERROR] {path}: {e}")
            elif choice == "manual":
                for path, family in self.detected_files:
                    confirm = QMessageBox.question(
                        self,
                        "Quarantine?",
                        f"[{family}] {path}\nQuarantine this file?",
                        QMessageBox.Yes | QMessageBox.No
                    )
                    if confirm == QMessageBox.Yes:
                        try:
                            os.remove(path)
                            self.output.append(f"[QUARANTINED] {path}")
                        except Exception as e:
                            self.output.append(f"[ERROR] {path}: {e}")
            else:
                self.output.append("Skipped all infected files.")

    def network_scan_action(self):
        self.output.append(">> Scanning Local Network...")
        devices = scan_network()
        if devices:
            self.output.append("Devices Found:")
            for dev in devices:
                self.output.append(f"- {dev}")
        else:
            self.output.append("No devices detected.")

# --- Run App ---
def run_app():
    os.environ["XDG_RUNTIME_DIR"] = "/tmp/runtime-root"
    app = QApplication(sys.argv)
    window = FerdiGhost()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    run_app()
