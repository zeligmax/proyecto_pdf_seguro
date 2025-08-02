Secure PDF Access System

🛡️ Project Overview

Secure PDF Access System is a desktop application built with Python that allows users to encrypt PDF documents, restrict access based on IP addresses, and automatically report unauthorized access attempts to a remote server. It is designed to protect sensitive PDF files from being accessed, shared, or stolen by unauthorized users.

📦 Features

Encrypt PDF files with AES (Fernet) encryption

Decrypt PDFs only if the user's IP is authorized (whitelisted)

Detect and log public IP addresses on document access

Automatically delete the encrypted PDF if access is denied

Upload PDF and download encrypted files via GUI

Modify whitelist IPs through a simple desktop interface

Send logs of access attempts to a remote Flask server

🖥️ Technologies Used

Python 3.11+

Tkinter (GUI)

PyInstaller (for packaging)

Cryptography (Fernet encryption)

Requests (for IP detection and logging)

Flask (remote server)

📁 Project Structure

PDF_SECURE/
├── app/
│ ├── app_gui.py # Main GUI application
│ ├── main.py # Console-based version
│ ├── config.py # Global config (encryption key, IP whitelist)
│ ├── ip_check.py # IP detection logic
│ ├── pdf_utils.py # Encryption/decryption functions
│ └── server_client.py # Log sending to remote server
├── server/
│ └── server.py # Flask server for logging access
├── icono.ico # (Optional) App icon for Windows
└── README.md

🚀 Getting Started

Clone this repository:

git clone https://github.com/your-username/secure-pdf-access.git
cd secure-pdf-access

Create a virtual environment:

python -m venv venv
source venv/bin/activate # On Windows: venv\Scripts\activate

Install dependencies:

pip install -r requirements.txt

Run the Flask server (for logging):

cd server
python server.py

Run the desktop app:

cd ../app
python app_gui.py

🔒 Encrypting a PDF

Open the GUI (app_gui.py)

Click “Select PDF to Encrypt” and choose a file

Click “Encrypt PDF”

The encrypted file will be saved as documento_encriptado.pdf

🔓 Decrypting a PDF

If your IP is whitelisted in config.py → WHITELISTED_IPS, the file will be decrypted

If not, it will be deleted and a log sent to the server

🛡️ Packaging as Executable

To generate a .exe on Windows:

pyinstaller --onefile --windowed --icon=icono.ico app_gui.py --add-data "config.py;."

For macOS (from a Mac):

pyinstaller --onefile --windowed --icon=icono.icns app_gui.py --add-data "config.py:."

📌 Note: Packaging for macOS must be done on a Mac.

📝 Configuration (config.py)

FERNET_KEY = b'...32-byte base64 key...'
WHITELISTED_IPS = [
"192.168.1.100", # Internal IP
"134.255.241.23" # Public IP
]

🧪 Testing

To test unauthorized access:

Temporarily remove your IP from the whitelist

Run the decryption attempt

Check that the file is deleted and log is sent

📃 License

MIT License — see LICENSE.md for details.

📬 Contact

Developed by ZELIGMAX
Questions or contributions? Feel free to open an issue or pull request.