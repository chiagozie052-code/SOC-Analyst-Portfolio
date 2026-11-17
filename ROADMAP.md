# Portfolio Roadmap

Ordered so each phase builds on the one before. A box gets checked once the write-up is published, not just once the room is finished.

**Cadence:** at least one new write-up a month. After each one, update the README table and post a short LinkedIn summary with the TryHackMe badge.

**Focus:** blue team, deep rather than wide (SOC → IR → identity threats). No red team detours.

## Phase 1 — Alert triage fundamentals
- [ ] TryHackMe SOC Simulator: phishing alert triage scenario
- [ ] Phishing analysis: email headers, URLs, attachments (*Phishing Analysis* / *Greenholt Phish*)
- [ ] Splunk basics write-up: building a SPL query library (*Splunk: Exploring SPL*)

## Phase 2 — Endpoint & log investigation
- [ ] Windows event log + Sysmon investigation (*Sysmon* / *Windows Event Logs*)
- [ ] Full Splunk incident (*Benign* or *Conti*)
- [ ] Elastic/Kibana investigation (*ItsyBitsy* / *Investigating with ELK 101*)

## Phase 3 — Network analysis
- [ ] Wireshark traffic analysis (*Wireshark: Traffic Analysis* / *Carnage*)
- [ ] IDS rule writing (*Snort Challenge — The Basics*)

## Phase 4 — Full incident write-ups (portfolio centerpieces)
- [ ] *Boogeyman 1*: phishing → endpoint → exfiltration
- [ ] *Tempest*: full IR across Sysmon + PCAP
- [ ] *Boogeyman 2/3*

## Phase 5 — Identity-focused (my differentiator)
- [ ] Identity attack investigation: password spray / MFA fatigue / impossible travel
- [ ] Detection queries for identity threats (SPL + KQL)
- [ ] Bring in the Python sign-in log analyzer → `/projects`

---

## Completed
| Date | Investigation | Link |
|---|---|---|
| 2026-11-16 | Phishing Unfolding (SOC Sim, Medium) | [write-up](investigations/thm-phishing-unfolding/) |
