# SOC Analyst Portfolio — Joseph Okafor

Hands-on security operations work: alert triage, log investigation, threat hunting, and detection writing. I'm an Identity & Access Management Analyst moving into security operations. Each investigation here is written the way I'd hand it to a Tier 2 analyst or incident lead.

> **About the lab environments:** Every investigation in this repo was done in a training environment (TryHackMe and similar platforms) on simulated data. Tools listed under *Lab tools* are skills I've practiced here; I don't claim them as production experience.

---

## About Me

I'm a security-focused IT professional with about three years in regulated financial services at Vanguard, Santander Bank and H&R Block, working under SOX, PCI-DSS and NIST-aligned security policies. Day to day, I review Okta authentication logs in Splunk to investigate access issues, triage tickets by risk and business impact, follow SOPs, document findings in ServiceNow and escalate per procedure. I work hands-on with Microsoft Entra ID, Azure, Active Directory, CyberArk and Intune.

This portfolio is where I build the SOC side: alert triage, phishing analysis, malware execution and network exfiltration, written up with the queries I ran and MITRE ATT&CK mapping. I'm looking for a Security Operations Center analyst role and I'm open to 24x7 shift work.

## Background

| | |
|---|---|
| **Current role** | IAM Analyst (SailPoint, CyberArk JIT, Okta, Entra ID), regulated financial services |
| **Certifications** | CompTIA Security+, CompTIA A+ |
| **Education** | B.S. Information Assurance & Cybersecurity, Capella University |
| **Production tools** | SailPoint IdentityIQ, Okta, Entra ID / Active Directory, CyberArk, Splunk (Okta auth logs), ServiceNow, PowerShell |
| **Lab tools** | Splunk SPL, Elastic/Kibana, Wireshark, Sysmon, Snort, CyberChef, MITRE ATT&CK Navigator |

---

## Investigations

Alert triage and incident write-ups. Each one covers the scenario, investigation steps with the queries I used, IOCs, MITRE ATT&CK mapping, a verdict, and recommended response.

| # | Investigation | Role | Platform | Focus | ATT&CK | Report |
|---|---|---|---|---|---|---|
| 1 | [Phishing Unfolding: Invoice Email to DNS Exfiltration](investigations/thm-phishing-unfolding/) | SOC Analyst · IR | TryHackMe SOC Sim | Phishing, PowerShell, reverse shell, DNS exfil | T1566.001, T1059.001, T1048.003 | 100% TP / 100% FP |

## Detections

Search queries and detection logic written during investigations, saved so they can be reused → [`/detections`](detections/)

## Progress

What I've finished and what's next → [`ROADMAP.md`](ROADMAP.md)

---

## How each write-up is structured

1. **Summary**: the alert, what happened, and the verdict, in a few lines
2. **Scenario & scope**: what I was given and what I was asked to find
3. **Investigation**: each step: question → query/action → finding (with screenshots)
4. **Indicators of compromise**: hashes, IPs, domains, accounts, files
5. **MITRE ATT&CK mapping**: tactics and techniques observed
6. **Timeline**: attacker activity in order
7. **Verdict & response**: true/false positive, severity, containment and remediation
8. **Lessons learned**: what I'd detect earlier next time

## Contact

[LinkedIn](https://www.linkedin.com/in/chiagozieokafor/)
