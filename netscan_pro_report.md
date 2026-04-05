# NetScan Pro — Project Report

---

## 1. Problem Statement

In today's interconnected digital landscape, network security remains a critical concern. System administrators and cybersecurity professionals need to regularly audit network hosts to identify open ports that may expose vulnerable services, leading to unauthorized access, data breaches, or ransomware attacks. Most existing port scanning tools are either command-line only (intimidating for beginners), require complex installation of third-party libraries, or lack visual risk assessment capabilities. There is a need for a lightweight, dependency-free, and user-friendly desktop application that combines fast multi-threaded port scanning, automatic service identification, real-time security risk classification, and exportable reporting — all within a modern graphical interface accessible to both beginners and professionals.

---

## 2. Detailed Description

**NetScan Pro** is an advanced network port scanner built entirely in Python's standard library. The application provides a complete port scanning workflow through a polished Tkinter-based graphical user interface.

### Core Capabilities

- **Multi-Threaded Scanning Engine** — Uses up to 500 concurrent threads via a semaphore-controlled thread pool, scanning thousands of ports in seconds. The scan of 1,024 well-known ports completes in under 2 seconds on a typical local network.

- **Service & Risk Database** — A built-in database of 70+ well-known ports maps each detected service (FTP, SSH, HTTP, SMB, RDP, MySQL, MongoDB, Redis, etc.) to a descriptive name, a security risk level, and a human-readable explanation of the vulnerability.

- **Four-Tier Risk Classification** — Every open port is categorized as **Critical**, **High**, **Medium**, or **Low** and displayed with distinct color-coded rows, enabling instant visual triage of the most dangerous exposures.

- **Banner Grabbing** — An optional feature that probes each open port to retrieve the service banner/header, revealing software versions (e.g., `Apache/2.4.41`, `OpenSSH_8.2`) for deeper analysis.

- **Real-Time Results** — Results populate into a sortable, filterable Treeview table as the scan progresses. A live progress bar, ports/second speed indicator, and elapsed timer provide continuous feedback.

- **Port Presets** — Six built-in presets (Top 20 Common, Web Ports, Database Ports, Well-Known 0–1023, Registered 1024–49151, All 0–65535) allow users to quickly configure scan scope.

- **Multi-Format Export** — Results can be exported as CSV (for spreadsheets), JSON (for automation/APIs), or formatted TXT reports (for documentation and sharing).

- **Scan History** — All completed scans are stored in-session and browsable through a dedicated History panel with target, port range, open count, duration, and timestamp.

- **Context Menu** — Right-clicking any result row provides options to copy the port, copy the full row, or open the service directly in a web browser.

- **DNS Resolution** — Hostnames are automatically resolved to IP addresses and displayed in the header bar.

---

## 3. End Users

| User Category | Use Case |
|---|---|
| **Cybersecurity Students** | Learning network fundamentals, understanding port/service relationships, and practicing security audits in lab environments |
| **IT & System Administrators** | Auditing internal network hosts, verifying firewall rules, and confirming that only intended services are exposed |
| **Penetration Testers** | Performing initial reconnaissance during authorized security assessments to map the target's attack surface |
| **Network Engineers** | Troubleshooting connectivity issues by verifying whether specific services are reachable on target hosts |
| **Small Business IT Staff** | Running quick security checks on office servers and infrastructure without needing enterprise-grade tools |
| **Hobbyists & Developers** | Verifying that development servers (Node.js, Flask, Django, databases) are running on expected ports |

---

## 4. Technology Used

| Component | Technology | Details |
|---|---|---|
| **Language** | Python 3.8+ | Core application language |
| **GUI Framework** | Tkinter + ttk | Native Python GUI toolkit with themed widgets |
| **Networking** | `socket` (stdlib) | TCP connect scanning via `connect_ex()` |
| **Concurrency** | `threading` (stdlib) | Multi-threaded scanning with semaphore-based worker pool (500 threads) |
| **Data Handling** | `csv`, `json` (stdlib) | Export functionality in multiple formats |
| **DNS** | `socket.gethostbyname()` | Hostname-to-IP resolution |
| **IP Validation** | `ipaddress` (stdlib) | Network address parsing and validation |
| **UI Patterns** | MVC-inspired | Scanner engine decoupled from GUI via thread-safe queue |
| **Platform** | Cross-platform | Windows, macOS, Linux (with platform-adaptive fonts and DPI awareness) |

> [!NOTE]
> **Zero external dependencies** — The entire application runs on Python's standard library. No `pip install` required.

---

## 5. Screenshot Analysis Report

![NetScan Pro — Completed Scan](c:\Users\Admin\Downloads\Network Port Scanner\screenshots\netscan_pro_preview.png)

### 5.1 Scan Summary

| Parameter | Value |
|---|---|
| **Target** | `192.168.31.240` (local network host) |
| **Port Preset** | Well-Known (0–1023) |
| **Ports Scanned** | 1,024 ports (0–1023) |
| **Open Ports Found** | 3 |
| **Scan Duration** | 1.64 seconds |
| **Scan Date** | 05 Apr 2026, 15:11:17 |

### 5.2 Open Ports Detected

| Port | Service | Risk Level | Description |
|---|---|---|---|
| **135** | MS-RPC | 🟠 **HIGH** | Microsoft RPC — common attack vector used in lateral movement and remote code execution |
| **139** | NetBIOS-SSN | 🟠 **HIGH** | NetBIOS Session Service — often exploitable for enumeration and unauthorized file sharing |
| **445** | SMB | 🔴 **CRITICAL** | Server Message Block — EternalBlue / ransomware vector (WannaCry, NotPetya, etc.) |

### 5.3 Risk Assessment

> [!WARNING]
> **The scanned host has 1 CRITICAL and 2 HIGH risk ports open.** No low-risk or informational ports were detected.

- **Port 445 (SMB) — CRITICAL**: This is the single most dangerous finding. SMB on port 445 has been the attack vector for some of the most devastating cyberattacks in history, including WannaCry (2017) and NotPetya. If this host is internet-facing, it is at extreme risk of exploitation. Even on internal networks, lateral movement via SMB is a primary technique used by ransomware.

- **Port 135 (MS-RPC) — HIGH**: Microsoft Remote Procedure Call is commonly targeted for remote code execution and is used by attackers for lateral movement within Windows environments. It should be blocked at the perimeter and restricted internally.

- **Port 139 (NetBIOS-SSN) — HIGH**: NetBIOS Session Service allows file and printer sharing. It is frequently abused for network enumeration (discovering hostnames, shares, users) and can facilitate unauthorized access to shared resources.

### 5.4 Recommendations

| # | Action | Priority |
|---|---|---|
| 1 | **Disable SMB v1** — Ensure SMBv1 is disabled on this host to mitigate EternalBlue-class exploits | 🔴 Critical |
| 2 | **Firewall Rules** — Block ports 135, 139, 445 from external/untrusted networks | 🔴 Critical |
| 3 | **Patch Management** — Verify Windows security updates are current, especially MS17-010 | 🟠 High |
| 4 | **Network Segmentation** — Isolate this host if it doesn't need to offer SMB/RPC services to the broader network | 🟠 High |
| 5 | **Re-scan with Banner Grabbing** — Enable the "Grab service banners" option and re-scan to identify exact software versions for vulnerability mapping | 🟡 Medium |

### 5.5 UI Observations

The screenshot demonstrates the following UI elements in action:

- **Sidebar** — Displays "LAST SCAN" stats: target IP, 3 open ports, 1.64s duration, along with navigation links (Scanner, History, About) and GitHub/version info.
- **Header Bar** — Shows resolved IP `192.168.31.240` and live date/time stamp.
- **Scan Configuration** — Target field populated, "Well-Known (0–1023)" preset selected, port range 0–1023 auto-filled.
- **Progress Bar** — Fully completed (100%), shown in blue.
- **Status Line** — Green checkmark with "Scan complete — 3 open ports found", "3 open ports" counter in green, and "Finished in 1.6s".
- **Results Table** — Three rows with color-coded risk: orange background for HIGH, red/pink background for CRITICAL.
- **Footer** — Clear, Search, JSON, TXT Report, and CSV export buttons all visible.

---

*Report generated on 05 April 2026 — NetScan Pro v2.0.0*
