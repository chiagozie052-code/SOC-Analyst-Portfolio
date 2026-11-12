# [Investigation Title]

| Field | Detail |
|---|---|
| **Platform** | TryHackMe — [room / SOC Simulator scenario name] |
| **Date** | YYYY-MM-DD |
| **Tools** | e.g. Splunk, Wireshark, CyberChef |
| **Data sources** | e.g. Sysmon, Windows Security logs, PCAP, email headers |
| **Verdict** | True Positive / False Positive / Benign True Positive |
| **Severity** | Low / Medium / High / Critical |

> Lab environment with simulated data, done for training.

---

## 1. Summary
<!-- 3–5 sentences: what the alert was, what you found, and the verdict. A busy lead should be able to stop reading here. -->

## 2. Scenario & Scope
<!-- What you were given (the alert, the logs, the time window) and what questions you had to answer. -->

## 3. Investigation

### Step 1 — [Question you were answering]
**Why:** <!-- why this was the next logical step -->

```spl
<!-- query you ran -->
```

**Finding:** <!-- what the output showed -->

![screenshot](../assets/screenshots/<folder>/step1.png)

### Step 2 — [Next question]
...

## 4. Indicators of Compromise

| Type | Value | Context |
|---|---|---|
| IP | `x.x.x.x` | C2 server |
| Domain | `example[.]com` | Phishing link (defanged) |
| SHA256 | `...` | Dropped payload |
| Account | `user@corp` | Compromised account |

## 5. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 | ... |

## 6. Timeline

| Time (UTC) | Event |
|---|---|
| | |

## 7. Verdict & Response
**Verdict:** <!-- TP/FP and why -->

**Containment:** <!-- isolate host, disable account, block IOCs -->

**Eradication & recovery:** <!-- remove persistence, reset creds, reimage -->

**Escalation:** <!-- would this go to Tier 2 / IR? why? -->

## 8. Lessons Learned
<!-- What detection would have caught this earlier? What would you do differently? -->
