# SOC-simulator

## Objective
Using TryHackMe SOC simulator to triage phishing alerts.

The objective of this lab is to show use of a real SOC environment.
Using the SOC dashboard, I will take ownership of alerts based on their severity, triage the alert, assign whether the alert is True positive or False positive, write a case report, and finally designate whether the alert needs escalation.

## Skills Learned

- **Email Security:** Investigate and mitigate phishing attempts and malicious attachments.
- **Incident Response:** Timely response and escalation of security incidents.
- **Log Analysis:** Proficient in using Splunk to analyze security events.
- **Threat Intelligence:** Cross-reference threats using intelligence sources.
- **Network Analysis:** Monitor and analyze network traffic with Wireshark.
- **File Analysis:** Inspect suspicious files using PowerShell and sandbox environments.
- **Documentation:** Create clear and concise incident reports.
- **Problem-Solving:** Strong critical thinking and troubleshooting skills.
- **Collaboration:** Work effectively with SOC teams.
- **Continuous Learning:** Stay updated with security trends and best practices.


## Tools Used

- **SOC Dashboard:** Monitored and managed security alerts and incidents.
- **Splunk Enterprise:** Analyzed security event logs and performed searches.
- **VM for Sandboxing:** Isolated environment for analyzing suspicious files.
- **VirusTotal:** Cross-referenced files and URLs with threat intelligence.
- **Wireshark:** Monitored and analyzed network traffic for suspicious activity.
- **PowerShell:** Conducted file analysis and automated tasks.

## Steps

Take ownership of an alert.

![SOC DashboardCapture](https://github.com/user-attachments/assets/bd557834-3f04-48a6-a00f-1e9cc9ddb497)

Once I took ownership of the alert, I read the alert description and continued my investigation using Splunk enterprise.

![Splunk enterpriseCapture](https://github.com/user-attachments/assets/0c271c6f-5790-4fa4-8dee-b7c302ab0f16)

The orginal email had no attachments and I found no replies by the recipient.
I assigned this alert a False positive and wrote the following Case Report:

Investigation Details:

Data Source: Emails
Steps Taken:

    1.  Reviewed Splunk logs for related email correspondence.
    2.  Confirmed that there was no reply to the original email.

Results:

    1.  No further actions or replies were detected.
    2.  The email domain (hatventuresworldwide.online) was flagged as unusual, but no malicious activity was identified.

Conclusion:
Determination: False Positive
Rationale:

    1. The initial suspicion was based on the unusual top-level domain.
    2. No further suspicious activity or follow-up actions were identified.

Action Taken:
Alert Classification: False Positive
Further Steps:

    1.  Fine-tune the detection rule to improve accuracy and reduce false positives.
    2.  Continue to monitor the environment for any similar alerts or unusual activities.
    3.  Provide training and awareness to employees on recognizing suspicious emails and reporting them.

![SOC DashboardCapture2](https://github.com/user-attachments/assets/b61d5aac-56e2-4f89-a483-87b55a868ec5)

![SOC DashboardCapture3](https://github.com/user-attachments/assets/f2c04130-145a-4716-8342-ade622616c3b)

I continued the process of triaging alerts as they came in.  A few had attachments that I was able to open in the VM that they provided (Sandbox). I was able to use the "more" command in Powershell to get more information about the attached file.
In one case you can see that if you were to run the file it was going to download a string installing powercat on the device.  A quick search of powercat shows that it can be used to gain remote control over the compromised system.  Leading to data exfil, persistence, lateral movement, and C2.

![VMCapture](https://github.com/user-attachments/assets/ff052ee4-bed4-458e-8843-46568bf58437)

I also used VirusTotal and some other outside sources to research these alerts.  I did find True positives that were documented and marked for escalation.
These phishing alerts were mostly low severity, but I am looking forward to the challenge of alerts of a higher severity, requiring more indepth investigation.



