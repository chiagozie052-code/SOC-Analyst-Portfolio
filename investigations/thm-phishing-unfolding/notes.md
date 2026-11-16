# Working notes: TryHackMe SOC Sim, Phishing Unfolding (started 2026-11-16)

Medium, ~40 min. A live phishing attack that unfolds across the corporate network; goal is to piece together the full attack chain and report it.

## Scenario objectives (from dashboard)
- Monitor and analyse real-time alerts as the attack unfolds
- Identify and document PowerShell executions, reverse shell connections, suspicious DNS requests
- Write case reports covering the full scope of the breach
- Alert categories shown: Phishing, Process, Execution

## Alerts worked
<!-- one section per alert: ID, rule, severity, key fields, queries run, verdict -->

### 1003: Suspicious email from external domain (Low, Phishing)
Screenshot: assets/screenshots/thm-phishing-unfolding/02-alert-1003-details.jpg
- 22:29:18, inbound email
- sender `leonard@fashionindustrytrends.xyz` → recipient `yani.zubair@tryhatme.com`
- subject: "Grow Your Hat Business Overnight with this Secret Formula"
- content: get-rich-quick pitch, "just click"; **no URL in body, no attachment**
- Rule note from SOC Lead: rule fires on unusual TLDs and "still needs fine-tuning"
- Verdict: **False Positive** (submitted and closed). Unsolicited marketing spam, not phishing: no link, no attachment, no credential request, so there's no way for it to cause harm. Rule fired on the .xyz TLD alone (rule flagged by SOC Lead as needing tuning).
- Tuning idea: only alert on unusual TLDs when the email also contains a URL or attachment

### Queue context at 22:31
- 1000 Suspicious email from external domain (22:26), not yet reviewed
- 1001 / 1002 Suspicious Parent Child Relationship (Process, 22:28 / 22:31)

## Attack chain (build as we go)
| Time | Stage | Evidence |
|---|---|---|

## Queries used

## End-of-session takeaway (fill in every time we stop)
- What I found:
- What it means for a SOC/IR role:

## Case study draft (Problem → Action → Outcome)
- Problem:
- Action:
- Outcome:
