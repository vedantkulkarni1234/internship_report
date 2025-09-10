# 🔐 Advanced Security Toolkit

A comprehensive collection of security tools including a steganography suite and a personal firewall, designed for both data protection and network security.

## 📁 Projects Overview

This repository contains two distinct security projects:

### 1. StealthyData - Steganography & Forensics Toolkit (Project_no_13)
### 2. CyberShield Firewall - Personal Network Firewall (Project_no_2)

---

## 🔒 StealthyData: Advanced Steganography & Forensics Toolkit

In the digital age, the need for secure communication and data protection has become paramount. Steganography, the practice of concealing information within other non-secret data, offers a sophisticated approach to hiding sensitive information in plain sight.

StealthyData is a comprehensive desktop application designed to provide both steganographic capabilities for hiding data and advanced forensic tools for data recovery and analysis.

### ✨ Features

* **Intuitive GUI**: A beautiful, modern dark-themed interface built with Tkinter
* **Drag & Drop**: Easily drag and drop images directly into the application
* **Dual Mode**:
  * **Hide Data**: Embed text messages or entire files within images
  * **Extract Data**: Recover the hidden information from stego-images
* **Multi-Algorithm Support**: Choose from a variety of steganography techniques:
  * **LSB (Least Significant Bit)**: Classic and simple
  * **Adaptive LSB**: Intelligently varies the number of bits used based on image complexity
  * **DCT (Discrete Cosine Transform)**: More robust against compression
  * **DWT (Discrete Wavelet Transform)**: Offers higher data hiding capacity and robustness
  * **Spread Spectrum**: Highly resistant to detection and removal attempts
* **Strong Encryption**: Secure your hidden data with password-based AES encryption (using PBKDF2 for key derivation)

### 🛡️ Advanced Forensics & Recovery Suite

StealthyData isn't just for hiding data; it's also a powerful tool for digital investigation.

* **Data Recovery**:
  * **Error Correction**: Attempt to recover data from corrupted images by cycling through different algorithms
  * **Partial Recovery**: Salvage readable fragments from heavily damaged data
  * **Brute-Force**: Automatically try a list of common passwords to decrypt data
* **Image Repair**:
  * Fix minor corruption in stego-images using various filtering and enhancement techniques (Median, Gaussian, etc.)
* **Forensic Analysis**:
  * **Basic Analysis**: Get metadata, timestamps, and file properties
  * **Deep Scan**: Perform advanced statistical tests (Chi-Square, Pair Analysis, RS Analysis) to detect the presence of hidden data
  * **LSB Entropy Analysis**: Check for unusual randomness in the least significant bits, a common sign of steganography
* **Brute-Force Protection**: The extraction process includes a simulated rate-limiter to demonstrate protection against password guessing attacks
* **Evidence Chain**:
  * Generate and verify data integrity reports (hashes, timestamps) for forensic evidence chains

### 🛠️ Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/vedantkulkarni1234/internship_report.git
   cd security-toolkit/Project_no_13
   ```

2. **Create a virtual environment (recommended)**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install the dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

### 🏃 Usage

To launch the application, simply run:
```bash
python main.py
```

---

## 🔥 CyberShield Firewall: Personal Network Firewall

A lightweight, Python-based personal firewall with a graphical user interface for monitoring and controlling network traffic.

### ✨ Features

* **Real-time Packet Monitoring**: Monitor incoming and outgoing network traffic in real-time
* **Rule-based Filtering**: Create custom rules to allow or block specific IP addresses, ports, and protocols
* **Intuitive GUI**: A user-friendly graphical interface to manage firewall rules, view logs, and monitor statistics
* **System Integration**: Integrates with `iptables` on Linux for system-level filtering
* **Logging and Auditing**: Detailed logs of all network activity and firewall actions
* **Customizable Rules**: Create, edit, and delete rules with different priorities

### 🛠️ Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/vedantkulkarni1234/internship_report.git
   cd security-toolkit/Project_no_2
   ```

2. **Install dependencies**:
   ```bash
   pip install scapy
   ```

### 🏃 Usage

To run the firewall with the GUI, execute the following command (requires root privileges on Linux):
```bash
sudo python3 firewall_gui.py
```

---

## 📋 Requirements

### StealthyData
* Python 3.9+
* tkinterdnd2>=0.3.0
* Pillow>=8.3.0
* cryptography>=3.4.8
* numpy>=1.21.0
* scipy>=1.7.0
* PyWavelets>=1.2.0

### CyberShield Firewall
* Python 3.6+
* scapy
* Root privileges for packet capture and `iptables` integration

---

## 🤝 Contributing

Contributions are welcome! If you have ideas for new features, bug fixes, or improvements, feel free to:

1. Fork the repository
2. Create a new feature branch (`git checkout -b feature/YourAmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/YourAmazingFeature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">
  <em>Made with ❤️ and Python</em>
</div>
