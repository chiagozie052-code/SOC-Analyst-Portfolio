# Working notes: TryHackMe SOC Sim, Introduction to Phishing (2026-11-12)

## Alert 8816: Access to Blacklisted External URL Blocked by Firewall (High)
- Timestamp: 11/12/2026 14:24:38
- Source: 10.20.2.17:34257 (internal host)
- Destination: 67.199.248.11:80 (TCP, web-browsing)
- URL: http://bit.ly/3sHkX3da12340 (URL shortener hides the real destination)
- Action: blocked; Rule: Blocked Websites
- Screenshot: assets/screenshots/thm-intro-to-phishing/01-alert-8816-details.jpg

### Context in the queue
- Phishing alerts "Inbound Email Containing Suspicious External Link": 8814 (14:22), 8815 (14:25), 8817 (14:27), 8818 (14:28)
- 8814 arrived about 2 min before the firewall block. Possibly related?

### Splunk search 1: `bit.ly` (6h real-time window) → 2 events
Screenshot: assets/screenshots/thm-intro-to-phishing/02-splunk-url-search.jpg
- 14:23:24 **email**, inbound
  - sender: `urgents@amazon.biz` | recipient: `h.harris@thetrydaily.thm`
  - subject: "Your Amazon Package Couldn't Be Delivered – Action Required"
  - body: failed delivery lure, "confirm shipping info" via http://bit.ly/3sHkX3da12340, 48h deadline. No attachment.
- 14:24:38 **firewall** block from 10.20.2.17 to the same URL, **74 seconds after delivery**

### Phishing indicators (my analysis)
1. Sender domain `amazon.biz` is a lookalike; Amazon doesn't send from `.biz`, and "urgents@" is not a real sending address
2. Generic greeting ("Dear Customer"). The real Amazon knows the account holder's name
3. Urgency/fear: "Action Required", 48-hour deadline, threat that the package will be returned
4. Link hidden behind a URL shortener (bit.ly) to conceal the real destination
5. Plain `http://`, not HTTPS, for a page that asks for personal/shipping info
6. Common pretext (failed delivery) that works on anyone who shops online

### Open questions
- [ ] Which user/host is 10.20.2.17?
- [ ] Where did the bit.ly link come from? (email?)
- [ ] Did any other host reach the URL (allowed, not blocked)?

### Asset inventory check
Screenshot: assets/screenshots/thm-intro-to-phishing/03-asset-inventory.jpg
- Only one entry: Office Network = 10.20.2.0/24 → 10.20.2.17 is an internal **office workstation**
- No IP-to-user mapping, so the link to h.harris rests on **timing correlation** (link clicked 74s after delivery to h.harris; only one recipient of this URL in logs)
- In production I'd confirm this with DHCP leases, EDR/endpoint inventory, or proxy auth logs
