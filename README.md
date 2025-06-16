# 🧪 cyber-homelab
This repository showcases hands-on cybersecurity projects built in my personal home lab. Each project focuses on practical blue team skills like log analysis, threat detection, SIEM triage, and network traffic investigation. 

Everything here is designed to simulate real-world SOC scenarios using tools like Splunk, Zeek, Sysmon, and Suricata. These projects help me turn technical learning into real, job-ready experience for a future role in a Security Operations Center.

## 🎯 Capstone Projects
Each capstone project is designed to reflect a critical SOC analyst skill area, building progressively toward real-world analyst readiness.
- [ ] **CP Lvl 1 – IOC Enrichment & Log Review**  
  _Analyze Sysmon/Windows logs and enrich IOCs using VirusTotal, AbuseIPDB, and Shodan._

- [ ] **CP Lvl 2 – Network Traffic Detection**  
  _Use Zeek and Wireshark to analyze PCAP data, detect suspicious activity, and map it to MITRE ATT&CK._

- [ ] **CP Lvl 3  – SIEM Alert Simulation**  
  _Create detection logic using Suricata and analyze alerts in Splunk or ELK. Perform triage and write a basic report._

- [ ] **CP Lvl 4 – Full Incident Response Simulation**  
  _Simulate a complete alert scenario from detection to documentation, including threat intel enrichment and escalation._

- [ ] **CP Lvl 5 – Threat Hunting Engagement**  
  _Form a hypothesis using MITRE TTPs, hunt across logs using SIEM or ELK data, and document investigation results._

## 🔧 Tools I’m Using
- **Nmap** – Network scanning, port discovery, and service enumeration
- **Wireshark** – Deep packet inspection and PCAP analysis
- **Metasploit** – Exploitation framework for testing detection and defense
- **ELK Stack (Elasticsearch, Logstash, Kibana)** – Log collection, search, and dashboarding
- **Zeek** – Network traffic monitoring and log generation for analysis
- **Suricata** – IDS/IPS engine for rule-based traffic detection
- **Sysmon** – Host-level event logging for Windows systems

## 🧠 Core Skills Practiced
- Host log analysis with Sysmon and Event Viewer
- Network traffic inspection using Zeek and Wireshark
- Alert triage, rule testing, and SIEM correlation (Splunk & ELK)
- Threat intelligence enrichment using OSINT (VirusTotal, Shodan, AbuseIPDB)
- MITRE ATT&CK mapping and investigation strategy
- Documentation and communication of investigation findings

## 🚨 Real-World Scenarios Simulated
- Investigating suspicious PowerShell behavior on a workstation
- Detecting and analyzing DNS tunneling attempts
- Triaging brute-force login events and simulating alert logic
- Responding to a simulated beaconing/malware C2 communication event
- Performing a threat hunt based on lateral movement hypotheses
