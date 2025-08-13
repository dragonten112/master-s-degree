# 🛡️ IP & CSV Anonymizer - Academic Privacy Toolkit

This is a Python-based GUI application that combines **IP anonymization using Tor** and **data anonymization in CSV files**. Designed for academic and testing environments, the tool helps protect personal data and explore privacy-focused technologies.

---

## 📌 Features

### 🔄 IP Rotator (via Tor)
- Rotates IP every 10 seconds using isolated SOCKS5 sessions
- Allows country selection for exit nodes (e.g., DE, US, FR)
- Verifies current IP using an external website
- Displays generated User-Agent and status of IP (new/duplicate)
- Visual loading animation (GIF) during rotation

### 📊 CSV Anonymizer
- Detects sensitive data (email, CNP, IP, card number, etc.) using regular expressions
- Applies masking and hashing to anonymize personal data
- Supports large CSV files (processed in chunks)
- Displays processing status with a real-time log in GUI

---

## 🛠️ Installation & Setup

### 🔰 Prerequisites

- Python 3.8+
- Tor service (running on ports 9050 and 9051)
- pip (Python package manager)

### 📦 Install Dependencies

```bash
pip install pandas fake-useragent stem requests python-dateutil pillow
```

> ✅ If `fake-useragent` fails, consider using a static user-agent string.

### 📁 Folder Setup

Make sure to include your CSV file in the project directory:

```
project-folder/
├── app.py
├── sample.csv
```

### 🚀 Run the Application

```bash
python app.py
```

---

## 🧅 Tor Configuration

Ensure the Tor control port is enabled. Example `torrc` config:

```
ControlPort 9051
CookieAuthentication 1
```

Start the Tor service before using the app:
- **Linux/macOS:** `sudo systemctl start tor`
- **Windows:** Run Tor Browser or Tor Expert Bundle

---

## 🔬 Technologies Used

- `tkinter` – GUI development
- `pandas` – CSV manipulation and processing
- `stem` – Interaction with the Tor network
- `requests` – IP detection via API
- `fake_useragent` – User-Agent randomization
- `regex`, `hashlib`, `ipaddress` – Data detection and transformation
- `Pillow` – For animated GIFs

---

## 📚 Purpose & Contribution

This project was developed as part of a **dissertation research** focused on user privacy, IP anonymization, and sensitive data protection. It combines practical tools with academic relevance, offering a user-friendly interface for experimentation.

---

## 🧪 Sample Use Cases

- Test how anonymized IPs interact with web services
- Mask sensitive identifiers before sharing datasets
- Educate students on data privacy tools

---

## 🤝 License

This project is intended for **educational and academic** use. For other uses, please check the license or contact the author.

---
