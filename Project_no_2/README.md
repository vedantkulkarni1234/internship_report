
# <p align="center">Personal Firewall</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/Ved-P/p-firewall/main/assets/banner.png" alt="Firewall Banner">
</p>

<p align="center">
  <b>A lightweight, Python-based personal firewall with a graphical user interface.</b>
</p>

<p align="center">
  <a href="https://github.com/Ved-P/p-firewall/blob/main/LICENSE"><img src="https://img.shields.io/github/license/Ved-P/p-firewall" alt="License"></a>
  <a href="https://github.com/Ved-P/p-firewall/releases"><img src="https://img.shields.io/github/v/release/Ved-P/p-firewall" alt="Version"></a>
  <a href="https://github.com/Ved-P/p-firewall/actions"><img src="https://img.shields.io/github/actions/workflow/status/Ved-P/p-firewall/python-app.yml?branch=main" alt="Build Status"></a>
  <a href="https://github.com/Ved-P/p-firewall/issues"><img src="https://img.shields.io/github/issues/Ved-P/p-firewall" alt="Issues"></a>
</p>

---

## 🔥 Features

- **Real-time Packet Monitoring:** Monitor incoming and outgoing network traffic in real-time.
- **Rule-based Filtering:** Create custom rules to allow or block specific IP addresses, ports, and protocols.
- **Intuitive GUI:** A user-friendly graphical interface to manage firewall rules, view logs, and monitor statistics.
- **System Integration:** Integrates with `iptables` on Linux for system-level filtering.
- **Logging and Auditing:** Detailed logs of all network activity and firewall actions.
- **Customizable Rules:** Create, edit, and delete rules with different priorities.

---

## 🚀 Getting Started

### Prerequisites

- Python 3.6+
- `scapy` library
- Root privileges for packet capture and `iptables` integration.

### Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/Ved-P/p-firewall.git
    cd p-firewall
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

### Running the Application

To run the firewall with the GUI, execute the following command:

```bash
sudo python3 firewall_gui.py
```

---

## 💻 Usage

The firewall application consists of a core engine and a GUI. The GUI provides a user-friendly interface to manage the firewall.

### Overview Tab

The **Overview** tab shows the real-time status of the firewall, including:

- **Firewall Control:** Start and stop the firewall.
- **Statistics:** View statistics on the number of packets processed, blocked, and allowed.
- **Recent Activity:** A live feed of the most recent network activity.

### Rules Tab

The **Rules** tab allows you to manage the firewall rules. You can:

- **Add a new rule:** Click the "Add Rule" button to open the rule editor.
- **Edit an existing rule:** Select a rule and click the "Edit Rule" button.
- **Delete a rule:** Select a rule and click the "Delete Rule" button.

### Logs Tab

The **Logs** tab displays a detailed log of all network activity. You can filter the logs by action (allow, block) and export them to a CSV file.

### Settings Tab

The **Settings** tab allows you to configure the firewall settings, including:

- **Network Interface:** Select the network interface to monitor.
- **Logging Settings:** Configure the logging level.
- **System Integration:** Install or remove `iptables` rules.

---

## 📸 Screenshots

<p align="center">
  <img src="https://raw.githubusercontent.com/Ved-P/p-firewall/main/assets/screenshot1.png" alt="Screenshot 1" width="45%">
  &nbsp; &nbsp; &nbsp;
  <img src="https://raw.githubusercontent.com/Ved-P/p-firewall/main/assets/screenshot2.png" alt="Screenshot 2" width="45%">
</p>

---

## 🤝 Contributing

Contributions are welcome! If you have any ideas, suggestions, or bug reports, please open an issue or create a pull request.

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
