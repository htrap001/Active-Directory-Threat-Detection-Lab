# SOC Detection Engine (Splunk)

This repository contains custom Security Operations Center (SOC) detection logic developed for a home lab environment. It transforms raw network and authentication logs into actionable security intelligence using Splunk Search Processing Language (SPL).

##  Project Overview

This project focuses on mitigating "alert fatigue" by moving away from logging every event to triggering high-fidelity alerts only when specific, suspicious thresholds are met. This setup simulates a real-world L1 SOC environment where incident response is driven by data-backed detections.

##  Detection Logic

The engine utilizes the following SPL queries to identify malicious activity:

### 1\. Nmap Port Scan Detection

Identifies reconnaissance activity by monitoring for an aggressive number of distinct port connections from a single source IP.

``` spl
index=* EventCode=5156 
| stats dc(DestPort) as Distinct_Ports_Hit, values(DestPort) as Targeted_Ports by SourceAddress
| where Distinct_Ports_Hit > 50

```

### 2\. SSH / RDP Brute Force Detection

Correlates rapid failed login events (`EventCode 4625`) with subsequent successful logins (`EventCode 4624`) to pinpoint potential compromised accounts.

``` spl
index=* (EventCode=4625 OR EventCode=4624)
| stats count(eval(EventCode=4625)) as Failed_Logins, count(eval(EventCode=4624)) as Successful_Logins, values(TargetUserName) as Attempted_Users by IpAddress
| where Failed_Logins > 10

```

### 3\. DoS / SYN flood detection

Monitors for network flooding by tracking the volume of packets sent to specific destination ports within 1-minute time buckets.

``` spl
index=* EventCode=5156
| bucket _time span=1m
| stats count as Packets_Per_Minute by SourceAddress, DestPort
| where Packets_Per_Minute > 500

```

##  Implementation steps

To deploy these detections in your Splunk instance:

1.  **Input:** Navigate to the Splunk Search bar and execute the desired query.
2.  **Create Alert:** Click **Save As \> Alert**.
3.  **Configure:**
      * **Type:** Scheduled (e.g., every hour/day).
      * **Condition:** Trigger when **Number of Results \> 0**.
      * **Action:** Enable **Add to Triggered Alerts** to maintain a searchable history of security incidents.
