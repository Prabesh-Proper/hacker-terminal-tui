# ⚡ HackerTerminal — TUI System Dashboard

A real-time, keyboard-navigable terminal dashboard ("btop-for-hackers") written in Python using **Textual** and **Rich**. 

HackerTerminal provides a single, high-fidelity monitoring interface that combines classic system metrics (CPU, RAM, GPU, and network rates) with security and administrative insights (open ports, active SSH connections, running services, active VPN tunnels, and local docker containers).

---

## 📸 Interface Overview

```text
+--------------------------------------------------------------------------------+
|  ⚡ HackerTerminal                                                    22:45:00  |
+--------------------------------------------------------------------------------+
| CPU: 12.5%           | RAM: 64.2%           | GPU: 0.0%                        |
| [██░░░░░░░░░░░░░░░░] | [████████████░░░░░░] | [░░░░░░░░░░░░░░░░░░]             |
| ▃▂ ▄▅▇█              | █▇▆▆▅▅▅▅             |                                  |
+----------------------+----------------------+----------------------------------+
| 📡 Network           | 🔓 Open Ports        | 🔑 SSH Sessions                  |
| 🌐 eth0              | 22/ssh               | 192.168.1.5:22 ←→ 10.0.0.3:54321 |
| ↓ 4.2KB/s  ↑ 1.1KB/s | 80/http              |                                  |
|                      | 443/https            |                                  |
| 🌐 wlan0             |                      |                                  |
| ↓ 0.0B/s   ↑ 0.0B/s  |                      |                                  |
+----------------------+----------------------+----------------------------------+
| ⚙️ Services           | 🐳 Docker            | 📶 WiFi Devices                  |
| systemd-journald     | a1b2c3d4e5f6         | wlan0                            |
| udev                 | nginx:latest         |                                  |
| docker               | running              |                                  |
+----------------------+----------------------+----------------------------------+
| 🔒 VPN Tunnels       |                                                         |
| tun0                 |                                                         |
+----------------------+---------------------------------------------------------+
| q Quit  r Refresh All                                                          |
+--------------------------------------------------------------------------------+
```

---

## 🚀 Features

- **Dynamic Resource Bar Gauges**: 
  - Real-time CPU, RAM, and GPU utilization.
  - Active color thresholds (Green `< 60%`, Yellow `60% - 80%`, Red `> 80%`).
  - 60-point **Sparkline trends** generated dynamically using Unicode block elements.
- **Real-Time Bandwidth Monitor**:
  - Live upload & download rates calculated per network interface.
- **Security & Port Audits**:
  - Checks TCP ports in `LISTEN` state and maps ports to service names (e.g., `80/http`).
  - Scans and visualizes established **SSH sessions** showing local/remote sockets.
- **Service & Container Overview**:
  - Lists running systemd services (falls back to top CPU-consuming processes on Windows/macOS).
  - Queries local Docker containers and shows their status, image, and ID.
- **Network Interface & VPN Watcher**:
  - Lists local network interfaces (using Scapy fallback if needed).
  - Detects active VPN tunnels (e.g., WireGuard, OpenVPN) via pyroute2 or `/proc`/`/sys` fallback.

---

## 🛠️ Cross-Platform Graceful Degradation

HackerTerminal is built defensively. If optional or OS-specific dependencies are missing, features degrade gracefully instead of crashing:
- **Windows / macOS**:
  - Systemd service scanning falls back to displaying top CPU-consuming processes.
  - Pyroute2 VPN interface scanning falls back to scanning sysfs and network interface stats.
  - Missing native binary utilities (like `nvidia-smi` or `docker`) are bypassed cleanly without throwing exceptions.
  - Socket scanning automatically catches and handles `AccessDenied` errors when executed without administrative or root privileges.

---

## 📦 Setup & Installation

### Prerequisites
- Python 3.8 or higher.

### Step-by-Step Guide

1. **Clone the Repository** (or copy this folder):
   ```bash
   git clone https://github.com/Prabesh-Proper/hacker-terminal-tui.git
   cd hacker-terminal-tui
   ```

2. **Create and Activate a Virtual Environment**:
   * **Linux/macOS**:
     ```bash
     python3 -m venv .venv
     source .venv/bin/activate
     ```
   * **Windows**:
     ```powershell
     python -m venv .venv
     .venv\Scripts\Activate.ps1
     ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the Dashboard**:
   ```bash
   python hackerminal.py
   ```

---

## ⌨️ Controls & Key Bindings

| Key | Action |
|---|---|
| `q` | Quit the application |
| `r` | Manually force refresh all stats |

---

## 📄 License

This project is open-source and licensed under the [MIT License](LICENSE).
