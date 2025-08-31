# 🛡️ Ferdi Ghost Defender

**Ferdi Ghost Defender** is a Python-based GUI antivirus scanner that detects malicious files such as **RATs**, **Backdoors**, **Viruses**, and other **Malware** using signature-based scanning.  
It features an interactive **post-scan threat control panel** so you can choose to **Delete All**, **Delete One-by-One**, or **Skip** infected files.

---

## ✨ Features
* 🔍 **Scan Files or Entire Folders**
* 🧾 **Threat Summary** after scan
* 🗑️ **Delete All**, **Delete Individually**, or **Skip**
* 💻 PyQt5-based GUI
* 📡 Quick links to social profiles

---

## 📦 Installation & Running

```bash
git clone https://github.com/ferdibrgll/Ferdi-Ghost-Defender.git
cd Ferdi-Ghost-Defender
pip3 install PyQt5
python3 ferdi.py
⚠️ Note: If you encounter errors during installation or running, try the following:

1️⃣ Externally-Managed Environment Error (Kali Linux)

If you see:

error: externally-managed-environment

Do this:

python3 -m venv venv
source venv/bin/activate
pip install PyQt5
python ferdi.py

Or force system-wide install (not recommended):

pip3 install --break-system-packages PyQt5

2️⃣ PyQt5 Not Found

If you see:

ModuleNotFoundError: No module named 'PyQt5'

Then install it:

pip3 install PyQt5

Or inside the virtual environment:

python3 -m venv venv
source venv/bin/activate
pip install PyQt5
python ferdi.py

3️⃣ Permission / Access Errors

During scanning or deletion, if you see PermissionError, run as sudo (be careful!):

sudo python3 ferdi.py