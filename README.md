# SOC Analyst Portfolio — Joseph Okafor

Hands-on security operations work: alert triage, log investigation, threat hunting, and detection writing. I'm an Identity & Access Management Analyst moving into security operations. Each investigation here is written the way I'd hand it to a Tier 2 analyst or incident lead.

> **About the lab environments:** Every investigation in this repo was done in a training environment (TryHackMe and similar platforms) on simulated data. Tools listed under *Lab tools* are skills I've practiced here; I don't claim them as production experience.

---

## Background

| | |
|---|---|
| **Current role** | IAM Analyst (SailPoint, CyberArk JIT, Okta, Entra ID), regulated financial services |
| **Certifications** | CompTIA Security+, Blue Team Level 1 (BTL1), CompTIA A+, CySA+ (in progress) |
| **Education** | B.S. Information Assurance & Cybersecurity, Capella University |
| **Production tools** | SailPoint IdentityIQ, Okta, Entra ID / Active Directory, CyberArk, Splunk (Okta auth logs), ServiceNow, PowerShell |
| **Lab tools** | Splunk SPL, Elastic/Kibana, Wireshark, Sysmon, Snort, CyberChef, MITRE ATT&CK Navigator |

---

## Investigations

Alert triage and incident write-ups. Each one covers the scenario, investigation steps with the queries I used, IOCs, MITRE ATT&CK mapping, a verdict, and recommended response.

| # | Investigation | Platform | Focus | ATT&CK | Verdict |
|---|---|---|---|---|---|
| — | *First write-up coming soon* | | | | |

## Detections

Search queries and detection logic written during investigations, saved so they can be reused → [`/detections`](detections/)

## Projects

Tools and builds → [`/projects`](projects/)

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

[LinkedIn](#) · [Portfolio site](#)
