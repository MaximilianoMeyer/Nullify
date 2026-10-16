# Nullify

![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=flat&logo=python&logoColor=white)
![PyQt5](https://img.shields.io/badge/GUI-PyQt5-41CD52?style=flat&logo=qt&logoColor=white)
![NIST](https://img.shields.io/badge/Standard-NIST%20800--88-005A9C?style=flat)

## Description

Nullify is a data sanitisation tool built around the *NIST 800-88* guidelines — the industry standard for media sanitisation. It provides a graphical interface for detecting and monitoring USB storage devices in real time, enabling operators to audit and sanitise connected media in a controlled, standards-compliant workflow. The tool is designed for security-conscious environments where traceable, verifiable data destruction is required.
---
## Screenshots

Main Interface
![Main Interface](https://github.com/MaximilianoMeyer/Nullify/blob/main/images/main_interface.png)

Scan
![Scan](https://github.com/MaximilianoMeyer/Nullify/blob/main/images/scan.png)

Android
![Android](https://github.com/MaximilianoMeyer/Nullify/blob/main/images/android.png)

Backup
![Backup](https://github.com/MaximilianoMeyer/Nullify/blob/main/images/backup.png)

Files
![Files](https://github.com/MaximilianoMeyer/Nullify/blob/main/images/files.png)

---

## Features

- 🔌 *Real-time USB device monitoring* — automatically detects devices as they are connected
- 📋 *Connected device enumeration* — lists all currently attached USB devices via lsusb
- 🖥️ *PyQt5 graphical interface* — clean, minimal GUI for device inspection and interaction
- 🔍 *YARA-based threat scanning* — integrates yara-python for malware pattern detection on media
- 🤖 *ML-assisted analysis* — leverages scikit-learn and transformers for intelligent data classification
- 📄 *PDF report generation* — produces sanitisation reports via reportlab for audit trails
- ⚙️ *YAML-driven configuration* — behaviour and sanitisation policies configurable via YAML files

## Tech Stack

| Technology | Purpose |
|---|---|
| *Python 3* | Core application language |
| *PyQt5* | Desktop GUI framework |
| *psutil* | System and process utilities |
| *pyudev* | Linux device event monitoring |
| *yara-python* | Malware/pattern scanning on media |
| *scikit-learn* | Machine learning–based data classification |
| *transformers* | NLP/deep learning model support |
| *reportlab* | PDF sanitisation report generation |
| *pyyaml* | YAML configuration parsing |

## Prerequisites

- Python *3.8+*
- A Linux-based operating system (required for pyudev and lsusb support)
- usbutils system package installed (lsusb command available)
- libusb development headers (for USB monitoring support)

bash
# Debian/Ubuntu
sudo apt install usbutils python3-pip python3-venv adb


## Getting Started

1. *Clone the repository*

bash

git clone https://github.com/MaximilianoMeyer/Nullify.git
cd Nullify


2. *Create and activate a virtual environment*

bash
python3 -m venv venv
source venv/bin/activate


3. *Install dependencies*

bash
pip install -r requirements.txt


> *Note:* Installing transformers and scikit-learn may take several minutes and requires a stable internet connection to download model assets.

## Usage

Launch the application with:

bash

python3 nullify.py


Once the GUI is open:

- The *text area* will automatically display information about any USB device plugged in while the application is running.
- Click *"click me"* to enumerate all currently connected USB devices using lsusb and display the output in the text area.
- Device events (connect/disconnect) are captured in real time and appended to the log view.

> The application must be run with sufficient privileges to access USB device information. If device details are not appearing, try running with sudo.

bash
sudo python3 main.py


## Project Structure


Nullify/
├── main.py           # Application entry point; GUI setup and USB event monitoring
├── nullify.py        # Core sanitisation logic (NIST 800-88 workflows)
└── requirements.txt  # Python dependency definitions


## Contributing

Contributions are welcome. To contribute:

1. Fork the repository
2. Create a feature branch (git checkout -b feature/your-feature)
3. Commit your changes (git commit -m 'Add your feature')
4. Push to the branch (git push origin feature/your-feature)
5. Open a Pull Request

Please ensure any new sanitisation methods align with the *NIST SP 800-88* guidelines and include appropriate test coverage.

## License

No license is currently specified for this project. Please contact the repository owner [@MaximilianoMeyer](https://github.com/MaximilianoMeyer) before using, modifying, or distributing this software.

---
