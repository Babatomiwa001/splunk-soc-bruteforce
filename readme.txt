# 🛡️ Splunk SOC Lab — SSH Brute Force Detection
---

## 📋 Project Overview

This project documents the end-to-end build of a home SOC (Security Operations Centre) lab using **Splunk Enterprise** as the SIEM, a **Windows 10 VM** as both the victim machine and log source, and **Kali Linux** as the attacker machine. The lab simulates a real-world **SSH brute force attack** using Hydra, detects it through Splunk SPL queries, triggers automated alerts, and visualises the attack in a custom SOC dashboard.

This project demonstrates core Tier 1 SOC analyst skills including log ingestion, threat detection, alert configuration, and dashboard building.

---

## 🏗️ Lab Architecture

```
┌─────────────────────────────────────────────────────┐
│                  VMware Workstation                 │
│                                                     │
│  ┌──────────────────────┐   ┌─────────────────────┐ │
│  │   Windows 10 VM      │   │   Kali Linux VM     │ │
│  │                      │   │                     │ │
│  │  - Splunk Enterprise │◄──│  - Hydra            │ │
│  │  - OpenSSH Server    │   │  - Password List    │ │
│  │  - Windows Event Log │   │                     │ │
│  │                      │   │  [Attacker]         │ │
│  │  [Victim + SIEM]     │   │                     │ │
│  └──────────────────────┘   └─────────────────────┘ │
│                                                     │
│               Network: VMware NAT                   │
└─────────────────────────────────────────────────────┘
```

---

## 🛠️ Tools & Technologies

| Tool | Version | Purpose |
|------|---------|---------|
| Splunk Enterprise | 10.2.2 | SIEM — Log ingestion, detection, dashboards |
| Windows 10 | Home Edition | Victim machine + log source |
| Kali Linux | Latest | Attacker machine |
| Hydra | v9.6 | SSH brute force simulation |
| OpenSSH Server | Built-in | Attack surface on Windows |
| VMware Workstation | Latest | Virtualisation platform |

---

## 📦 Prerequisites

- VMware Workstation or VMware Fusion installed
- Minimum **16GB RAM** on host machine
- Windows 10 VM (any edition)
- Kali Linux VM
- Free Splunk account at [splunk.com](https://www.splunk.com)

---

## ⚙️ Setup & Installation

### 1. Install Splunk Enterprise on Windows 10 VM

1. Download **Splunk Enterprise for Windows (.msi)** from [splunk.com/download](https://www.splunk.com/en_us/download/splunk-enterprise.html)
2. Run the installer — select **Local System** for user account
3. Set your admin credentials during installation
4. Launch Splunk at `http://localhost:8000`

### 2. Configure Windows Event Log Ingestion

1. In Splunk → **Settings → Add Data → Monitor → Local Event Logs**
2. Select the following log channels:
   - ✅ Security
   - ✅ System
   - ✅ Application
3. Complete the wizard and confirm data is flowing:

```spl
index=* earliest=-60m
| table _time, index, sourcetype, host
```

### 3. Install OpenSSH Server on Windows 10

Open **Command Prompt as Administrator:**

```cmd
# Enable OpenSSH Server via Settings > Apps > Optional Features > Add Feature > OpenSSH Server
# Then start and configure the service:

net start sshd
sc config sshd start=auto

# Allow through Windows Firewall:
netsh advfirewall firewall add rule name="OpenSSH" dir=in action=allow protocol=TCP localport=22

# Verify it's listening:
netstat -an | findstr :22
```

### 4. Configure Kali Linux VM Network

- Set both VMs to **NAT** in VMware network settings
- Verify connectivity from Kali:

```bash
ping <Windows-VM-IP>
```

---

## ⚔️ Attack Simulation

### Create Password Wordlist on Kali

```bash
nano ~/passwords.txt
```

Add entries including the target password at an unknown position:

```
admin
password
123456
Welcome1
Password1
Lab@12345
letmein
abc123
qwerty
Password123
```

### Launch Hydra SSH Brute Force

```bash
hydra -l <username> -P ~/passwords.txt ssh://<Windows-IP> -t 1 -W 3 -v -I
```

**Flags explained:**
- `-l` — Target username
- `-P` — Password wordlist
- `-t 1` — 1 thread (avoids lockout)
- `-W 3` — 3 second wait between attempts
- `-v` — Verbose output
- `-I` — Skip restore file prompt

**Expected Output:**
```
[INFO] Testing if password authentication is supported by ssh://user@192.168.x.x:22
[ATTEMPT] target 192.168.x.x - login "user" - pass "admin"
[ATTEMPT] target 192.168.x.x - login "user" - pass "password"
...
[22][ssh] host: 192.168.x.x  login: user  password: Lab@12345
```

---

## 🔍 Splunk Detection — SPL Queries

### Query 1 — Detect All Failed Logins

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4625
| table _time, Account_Name, Logon_Type, Message
| sort - _time
```

### Query 2 — Count Failures by Account (Brute Force Pattern)

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4625
| stats count by Account_Name
| sort - count
```

### Query 3 — Compare Failures vs Successes (Account Takeover Pattern)

```spl
index=main sourcetype="WinEventLog:Security" EventCode IN (4624, 4625)
| stats count by EventCode, Account_Name
| sort Account_Name
```

### Query 4 — Automated Alert Threshold Query

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4625
| stats count by Account_Name
| where count >= 5
```

---

## 🚨 Key Windows Security Event Codes

| EventCode | Description | Significance |
|-----------|-------------|--------------|
| **4624** | Successful logon | Baseline / post-attack success |
| **4625** | Failed logon | Core brute force indicator |
| **4648** | Logon with explicit credentials | Lateral movement indicator |
| **4672** | Special privileges assigned | Privilege escalation indicator |

---

## 🔔 Automated Alert Configuration

Alert triggers automatically when any account accumulates 5+ failed logins:

| Setting | Value |
|---------|-------|
| Alert Name | `Brute Force - Multiple Failed Logins` |
| Search | `EventCode=4625 \| stats count by Account_Name \| where count >= 5` |
| Schedule | Every 5 minutes |
| Trigger Condition | Number of Results > 0 |
| Severity | High |
| Action | Add to Triggered Alerts |

---

## 📊 SOC Dashboard

A custom **SOC - Brute Force Monitor** dashboard was built with 4 panels:

| Panel | Visualization | Query |
|-------|--------------|-------|
| Failed Logins Over Time | Line Chart | `EventCode=4625 \| timechart count span=5m` |
| Top Targeted Accounts | Bar Chart | `EventCode=4625 \| stats count by Account_Name` |
| Total Failed Logins | Single Value | `EventCode=4625 \| stats count` |
| Recent Failed Login Events | Table | `EventCode=4625 \| table _time, Account_Name, Message \| head 20` |

### Dashboard Screenshot

> The dashboard showed **35 failed SSH attempts** against the target account, with two distinct attack spikes visible on the timeline — each corresponding to a Hydra brute force run.

---

## 📁 Project Structure

```
splunk-soc-lab/
│
├── README.md                  # This file
├── queries/
│   ├── detection_queries.spl  # All SPL detection queries
│   └── dashboard_queries.spl  # Dashboard panel queries
├── screenshots/
│   ├── splunk_dashboard.png   # SOC dashboard overview
│   ├── failed_logins.png      # 4625 event results
│   └── hydra_output.png       # Hydra attack output
└── alerts/
    └── brute_force_alert.xml  # Exported Splunk alert config
```

---

## 🧠 Skills Demonstrated

- ✅ SIEM deployment and configuration (Splunk Enterprise)
- ✅ Windows Event Log ingestion and parsing
- ✅ SPL (Search Processing Language) query writing
- ✅ Brute force attack simulation using Hydra
- ✅ Threat detection via EventCode analysis
- ✅ Automated alert creation and tuning
- ✅ SOC dashboard design and visualisation
- ✅ Incident identification using the PICERL framework
- ✅ MITRE ATT&CK mapping: **T1110 — Brute Force**

---

## 🗺️ MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Credential Access | Brute Force: Password Guessing | T1110.001 |
| Initial Access | Valid Accounts | T1078 |
| Lateral Movement | Remote Services: SSH | T1021.004 |

---

## 🔮 Future Improvements

- [ ] Integrate Splunk Universal Forwarder for remote log shipping
- [ ] Add Sysmon for enhanced Windows endpoint telemetry
- [ ] Simulate privilege escalation and detect via EventCode 4672
- [ ] Build correlation searches linking brute force → successful login
- [ ] Integrate threat intelligence feeds (OSINT IP lookup)
- [ ] Add GeoIP lookup to visualise attacker location on a map

---

## 👤 Author

**Babatomiwa (Israel Joshua)**
Cybersecurity Professional | Lagos, Nigeria

(https://linkedin.com/in/israel-joshua-572055153)

**Certifications:**
- Cisco CyberOps Associate
- Cisco Certified Ethical Hacker
- CompTIA Security+ *(In Progress — SY0-701)*

---

## 📄 License

This project is for educational purposes only. All attack simulations were conducted in an isolated lab environment. Do not use these techniques against systems you do not own or have explicit permission to test.

---

> *"The best way to learn cybersecurity is to build the lab, break things, and detect them yourself."*