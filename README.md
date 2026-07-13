# Active Directory Threat Detection Lab

A fully functional Home Lab designed to simulate real-world cyberattacks from an adversary machine (Kali Linux), log the malicious activity on a target enterprise network (Windows Server 2022 Active Directory Domain Controller), and ingest, parse, and analyze the resulting telemetry using a Centralized SIEM (**Splunk Enterprise**).[cite: 1]

---

## 🛠️ Lab Architecture & Components

The environment is distributed across two physical host machines to accurately simulate a network boundary, utilizing a **Splunk Universal Forwarder (UF)** to securely ship event logs.[cite: 1]




```
   [ Kali Linux VM ] (Attacker)
           │
           ▼ (SMB / RPC Brute Force Attacks)
```
```

[ Windows Server 2022 DC ] (Target Core)
│
▼ (Splunk Universal Forwarder)
[ Splunk Enterprise ] (SIEM Engine)

```

*   **SIEM Node (Host 1 - Intel i5 Laptop):** 
    *   **OS:** Windows 11 Local Host[cite: 1]
    *   **Deployment:** Splunk Enterprise Server (Indexer & Search Head)[cite: 1]
*   **Target & Attack Environment (Host 2 - Intel i7 Laptop):**
    *   **Domain Controller:** Windows Server 2022 Evaluation Copy (Active Directory Services, DNS).[cite: 1]
    *   **Endpoint Telemetry Agent:** Splunk Universal Forwarder + Microsoft Sysmon.[cite: 1]
    *   **Attacker Platform:** Kali Linux fully loaded with network exploitation toolsets (`CrackMapExec` / `NetExec`).[cite: 1]

---

## 🚀 Attack Simulation Scenario

### Phase 1: High-Frequency Authentication Abuse (Standard Brute Force)
*   **Objective:** Gain unauthorized access to Active Directory domain accounts by systematically testing a massive list of potential password strings against targeted usernames.
*   **Execution (Kali Linux):** Targeted the Active Directory SMB service using a pre-compiled password dictionary list against domain users.[cite: 1]
    ```bash
    crackmapexec smb 192.168.1.50 -u /usr/share/wordlists/metasploit/namelist.txt -p 'Password123!'
    ```
*   **Mechanism:** This generates an immediate, high-density spike of authentication failures as the attack platform rapidly cycles through potential credential combinations against the Domain Controller.[cite: 1]

---

## 🔍 SIEM Engineering & Telemetry Analysis

### Detecting Brute Force Tactics
Standard Windows Event logging maps these malicious access anomalies to **Windows Event ID 4625** (An account failed to log on).[cite: 1]

Because different ingestion pipelines map Windows variables uniquely based on the log format (raw text vs. structured XML), a resilient **coalesce-driven** search query was engineered in Splunk to uniformly normalize disparate schema outputs (`IpAddress`, `Source_Network_Address`, `src_ip`) into clean analytical views.[cite: 1]

#### Production Splunk SPL Query:
```splunk
index=* EventCode=4625
| eval Attacker_IP = coalesce(IpAddress, Source_Network_Address, src_ip)
| eval Targeted_User = coalesce(TargetUserName, Account_Name, user)
| stats count min(_time) as first_seen max(_time) as last_seen by Attacker_IP, Targeted_User
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S"), last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
| sort - count
```[cite: 1]

#### Captured Telemetry Output:
When the brute force attack was deployed, the Splunk engineering pipeline successfully aggregated, isolated, and highlighted the exact signature of the threat actor:[cite: 1]

| Attacker_IP | Targeted_User | count | first_seen | last_seen |
| :--- | :--- | :--- | :--- | :--- |
| `192.168.1.12` | `Administrator` | `45` | 2026-07-13 14:15:22 | 2026-07-13 14:16:10 |
| `192.168.1.21` | `parth` | `1909` | 2026-07-13 14:15:23 | 2026-07-13 14:16:12 |
| `192.168.1.21` | `guest` | `12` | 2026-07-13 14:15:24 | 2026-07-13 14:15:55 |

---

## 📈 Lab Optimization & Hardening Steps
1.  **Sysmon Integration:** Deployed Microsoft System Monitor utilizing custom rulesets to bridge visibility gaps surrounding process spawning hierarchies and network hooks initiated during authentication floods.[cite: 1]
2.  **Field Extraction Tuning:** Implemented structured field alias rules within Splunk's configuration parsing layer (`props.conf`) to automate data normalization without relying on manual run-time evaluations.[cite: 1]
3.  **Threshold Ingestion Rules:** Configured alert rules to flag whenever a unique internal asset generates more than twenty login disruptions within a sixty-second window.[cite: 1]

---
*Developed as an engineering capstone to demonstrate proficiency in Security Operations, SIEM engineering, log normalization, and Active Directory threat vectors.*[cite: 1]

```
