# Active Directory Threat Detection Lab

A fully functional Home Lab designed to simulate real-world cyberattacks from an adversary machine (Kali Linux), to log the malicious activity on a target enterprise network (Windows Server 2022 Active Directory Domain Controller), and to ingest, parse, and analyze the resulting telemetry using a Centralized SIEM (**Splunk enterprise**).

---

##  Lab architecture & components

The environment is distributed across two physical host machines to accurately simulate a network boundary, utilizing a **Splunk universal forwarder** to securely ship event logs.
  **Virtualization:** Oracle virtualbox.



```
   [ Kali linux VM ] (Attacker)
           │
           ▼ (SMB brute force attacks)
```
```

[ Windows server 2022 DC ] (Target core)
│
▼ (Splunk universal forwarder)
[ Splunk enterprise ] (SIEM engine)

```

*   **SIEM node (Host 1 -i5 Laptop):** 
    *   **OS:** Windows 11 home Local Host
    *   **Deployment:** Splunk enterprise server (Indexer & search head)
*   **Target & attack environment (Host 2 -i7 Laptop):**
    *   **Domain controller:** Windows Server 2022 Evaluation Copy (Active Directory Services, DNS).
    *   **Endpoint telemetry agent:** Splunk Universal Forwarder + Microsoft Sysmon.
    *   **Attacker platform:** Kali Linux VM fully loaded with network exploitation toolsets.

---

##  Attack simulation scenario

### Phase 1: High-frequency authentication abuse (standard brute force)
*   **Objective:** To gain unauthorized access to Active Directory domain accounts by systematically testing a massive list of potential password strings against targeted usernames.
*   **Execution (in kali linux):** Targeted the Active Directory SMB service using a pre-compiled password dictionary list against domain users.
    ```bash
    crackmapexec smb 192.168.0.109 -u /usr/share/wordlists/metasploit/namelist.txt -p 'Password123!'
    ```
*   **Mechanism:** This generates an immediate, high-density spike of authentication failures as the attack platform rapidly cycles through potential credential combinations against the Domain Controller.
  <img width="1917" height="1078" alt="Screenshot 2026-07-13 170658" src="https://github.com/user-attachments/assets/7b155f6f-0072-439a-9858-d9495fc0b1c3" />


---

##  SIEM engineering & telemetry analysis

### Detecting Brute Force Tactics
Standard Windows Event logging maps these malicious access anomalies to **Windows Event ID 4625** (An account failed to log on).

At the time of SMB attack, i had already opened up splunk enterprise on different laptop i.e the one with i5. Search query:
```
index=wineventlog
```
and i selected Real time. So alerts with event code 4625 (failed logon attempt) started to flood in.
<img width="1920" height="1080" alt="Realtime" src="https://github.com/user-attachments/assets/7d3af774-9927-418f-879c-2a54e00618a0" />
<img width="1920" height="1080" alt="event flood" src="https://github.com/user-attachments/assets/695ab2bc-6766-4119-ab31-97ac6153382f" />

Because different ingestion pipelines map Windows variables uniquely based on the log format (raw text vs. structured XML), then with help of Splunk documentation and some google searches, i wrote a search query to uniformly normalize disparate schema outputs (`IpAddress`, `Source_Network_Address`, `src_ip`) into clean analytical view.

#### Splunk SPL query:
```splunk
index=wineventlog EventCode=4625
| eval Attacker_IP = coalesce(IpAddress, Source_Network_Address, src_ip)
| eval Targeted_User = coalesce(TargetUserName, Account_Name, user)
| stats count min(_time) as first_seen max(_time) as last_seen by Attacker_IP, Targeted_User
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S"), last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
| sort - count
```

#### Captured telemetry output after above search query:
When the brute force attack was deployed, the Splunk engineering pipeline successfully aggregated, isolated, and highlighted the exact signature of the threat actor:
<img width="1920" height="1080" alt="Search query" src="https://github.com/user-attachments/assets/f9dc9952-82d6-4820-882e-3e4929013a65" />


---

##  Lab optimization & hardening steps
1.  **Sysmon integration:** Deployed Microsoft System Monitor utilizing custom rulesets to bridge visibility gaps surrounding process spawning hierarchies and network hooks initiated during authentication floods.[cite: 1]
2.  **Field extraction tuning:** Implemented structured field alias rules within Splunk's configuration parsing layer (`props.conf`) to automate data normalization without relying on manual run-time evaluations.[cite: 1]
3.  **Threshold ingestion rules:** Configured alert rules to flag whenever a unique internal asset generates more than twenty login disruptions within a sixty-second window.[cite: 1]

## Converted it itno a splunk dashboard
<img width="1920" height="1080" alt="Dashboard" src="https://github.com/user-attachments/assets/64b7cf10-ed02-42d8-8b29-56e0305498f2" />

*Developed as an capstone to demonstrate proficiency in Security operations, SIEM engineering, log normalization, and Active directory threat vectors.*
