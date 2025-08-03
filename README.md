# 🔐 PDF Secure

**PDF Secure** is a desktop and command-line application that encrypts and decrypts PDF files with an extra layer of IP-based security. Only authorized IP addresses can access the protected documents.

---

## ✨ Features

- Encrypt and decrypt PDF files using symmetric encryption (Fernet/AES).
- IP whitelisting: only specific IPs can decrypt the file.
- User-friendly graphical interface (Tkinter).
- Command-line interface (CLI) included.
- Manageable whitelist of IPs.
- Cross-platform: works on Windows, Linux, and macOS.

---

## 📦 Requirements

- Python 3.8 or higher
- Packages: `cryptography`, `tkinter` (usually included with Python)

Install the required packages with:

```bash
pip install cryptography

🚀 Installation
Clone the repository:

bash
Copiar
Editar
git clone https://github.com/zeligmax/proyecto_pdf_seguro.git
cd proyecto_pdf_seguro
🖥️ GUI Usage
Run the GUI with:

bash
Copiar
Editar
python app/app_gui.py
From the interface, you can:

Encrypt a PDF file.

Decrypt a .enc file.

Add or remove IPs from the whitelist.

🧪 CLI Usage
Run the app in the terminal:

bash
Copiar
Editar
python app/main.py
Then follow the prompts:

Option 1: Encrypt a PDF

Option 2: Decrypt a protected file

🔐 IP-Based Access Control
When encrypting a PDF, a list of authorized IPs is embedded. Only those IPs can decrypt the file, preventing unauthorized distribution.

You can manage the whitelist via the GUI or by editing config.py directly.

📁 Project Structure
bash
Copiar
Editar
proyecto_pdf_seguro/
│
├── app/
│   ├── app_gui.py        # GUI interface
│   ├── main.py           # CLI interface
│   ├── pdf_utils.py      # PDF encryption/decryption logic
│   ├── ip_check.py       # IP detection and validation
│   ├── config.py         # App settings: Fernet key and IP whitelist
│   └── ...
│
└── README.md

📜 License
This project is licensed under the MIT License. See the LICENSE file for details.

🤝 Contributing
Contributions are welcome! Feel free to:

Open issues

Submit pull requests

Suggest improvements

🧠 Author
Developed by @zeligmax

