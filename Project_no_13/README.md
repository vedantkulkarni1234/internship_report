<div align="center">
  <!-- 
  NOTE: You can replace this placeholder with a real logo.
  For example: <img src="assets/logo.png" alt="Logo" width="150">
  -->
  <h1>StealthyData 🔒</h1>
  <p><strong>The Ultimate Steganography & Forensics Toolkit</strong></p>
  <p>
    <em>Hide your secrets in plain sight. Uncover hidden data with powerful forensic tools.</em>
  </p>
  <p>
    <a href="#"><img alt="Python Version" src="https://img.shields.io/badge/python-3.9%2B-blue.svg?style=for-the-badge&logo=python"></a>
    <a href="#"><img alt="License" src="https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge"></a>
    <a href="#"><img alt="Status" src="https://img.shields.io/badge/status-active-brightgreen.svg?style=for-the-badge"></a>
  </p>
</div>

---

## ✨ Introduction

**StealthyData** is a sophisticated, feature-rich desktop application designed for steganography — the art of hiding information within other non-secret files. Built with a sleek and intuitive user interface, it provides a comprehensive suite of tools for both embedding and extracting data from images, as well as an advanced forensics toolkit for analysis and recovery.

Whether you're a security enthusiast, a digital forensics professional, or just curious about secret communication, StealthyData offers the power and flexibility you need.

<div align="center">
  <!-- 
  NOTE: You should replace this placeholder with a real screenshot or GIF of your application.
  For example: <img src="assets/screenshot.gif" alt="StealthyData in action">
  -->
  <p><em>[Screenshot of the application]</em></p>
</div>

---

## 🚀 Core Features

*   **Intuitive GUI**: A beautiful, modern dark-themed interface built with Tkinter.
*   **Drag & Drop**: Easily drag and drop images directly into the application.
*   **Dual Mode**:
    *   **Hide Data**: Embed text messages or entire files within images.
    *   **Extract Data**: Recover the hidden information from stego-images.
*   **Multi-Algorithm Support**: Choose from a variety of steganography techniques:
    *   **LSB (Least Significant Bit)**: Classic and simple.
    *   **Adaptive LSB**: Intelligently varies the number of bits used based on image complexity.
    *   **DCT (Discrete Cosine Transform)**: More robust against compression.
    *   **DWT (Discrete Wavelet Transform)**: Offers higher data hiding capacity and robustness.
    *   **Spread Spectrum**: Highly resistant to detection and removal attempts.
*   **Strong Encryption**: Secure your hidden data with password-based AES encryption (using PBKDF2 for key derivation).

---

## 🛡️ Advanced Forensics & Recovery Suite

StealthyData isn't just for hiding data; it's also a powerful tool for digital investigation.

*   **Data Recovery**:
    *   **Error Correction**: Attempt to recover data from corrupted images by cycling through different algorithms.
    *   **Partial Recovery**: Salvage readable fragments from heavily damaged data.
    *   **Brute-Force**: Automatically try a list of common passwords to decrypt data.
*   **Image Repair**:
    *   Fix minor corruption in stego-images using various filtering and enhancement techniques (Median, Gaussian, etc.).
*   **Forensic Analysis**:
    *   **Basic Analysis**: Get metadata, timestamps, and file properties.
    *   **Deep Scan**: Perform advanced statistical tests (Chi-Square, Pair Analysis, RS Analysis) to detect the presence of hidden data.
    *   **LSB Entropy Analysis**: Check for unusual randomness in the least significant bits, a common sign of steganography.
*   **Brute-Force Protection**: The extraction process includes a simulated rate-limiter to demonstrate protection against password guessing attacks.
*   **Evidence Chain**:
    *   Generate and verify data integrity reports (hashes, timestamps) for forensic evidence chains.

---

## 🛠️ Installation

Get StealthyData up and running in a few simple steps.

1.  **Clone the repository (or download the source):**
    ```bash
    git clone https://github.com/your-username/Steganography.git
    cd Steganography
    ```

2.  **Create a virtual environment (recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3.  **Install the dependencies:**
    The project comes with a `requirements.txt` file to simplify this process.
    ```bash
    pip install -r requirements.txt
    ```

---

## 🏃‍♀️ Usage

To launch the application, simply run the `main.py` script:

```bash
python main.py
```

---

## 📖 How to Use

### To Hide Data

1.  **Launch** the application.
2.  Go to the **Hide Data** tab.
3.  **Drag & drop** your cover image or click **Browse Image**.
4.  **Select the Data Type**: "Text Message" or "File".
5.  **Input your data**:
    *   If "Text Message", type your secret message.
    *   If "File", click "Browse" to select the file you want to hide.
6.  **Choose an Algorithm** (e.g., LSB, DCT).
7.  **(Optional but Recommended)** Check **"Encrypt data with password"** and enter a strong password.
8.  Click the **"Hide Data in Image"** button.
9.  **Save** the new stego-image to your desired location.

### To Extract Data

1.  **Launch** the application.
2.  Go to the **Extract Data** tab.
3.  **Drag & drop** the stego-image or click **Browse Stego Image**.
4.  **Select the Algorithm** that was used to hide the data.
5.  If the data was encrypted, check **"Data is encrypted"** and enter the correct password.
6.  Click the **"Extract Hidden Data"** button.
7.  The extracted message will appear in the text box. If a file was extracted, you'll be prompted to save it.

---

## 🤝 Contributing

Contributions are welcome! If you have ideas for new features, bug fixes, or improvements, feel free to:

1.  Fork the repository.
2.  Create a new feature branch (`git checkout -b feature/YourAmazingFeature`).
3.  Commit your changes (`git commit -m 'Add some AmazingFeature'`).
4.  Push to the branch (`git push origin feature/YourAmazingFeature`).
5.  Open a Pull Request.

---

## 📜 License

This project is licensed under the MIT License.

---

<div align="center">
  <em>Made with ❤️ and Python</em>
</div>
