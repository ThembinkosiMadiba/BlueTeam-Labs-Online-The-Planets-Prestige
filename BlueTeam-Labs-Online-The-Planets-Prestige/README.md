# 🔍 Phishing Email Investigation — SOC Analysis Case Study

### BlueTeam Labs Online | The Planet's Prestige

> **Platform:** BlueTeam Labs Online  
> **Challenge:** The Planet's Prestige  
> **Category:** CTF / Email Forensics  
> **Difficulty:** Easy  
> **Points:** 10  
> **Completed:** March 12, 2026  
> **Status:** ✅ Completed

---

## Table of Contents

1. [Introduction](#introduction)
2. [Investigation Overview](#investigation-overview)
3. [Email Metadata Analysis](#email-metadata-analysis)
4. [Email Authentication Analysis](#email-authentication-analysis)
5. [Base64 Payload Analysis](#base64-payload-analysis)
6. [IP Address Investigation](#ip-address-investigation)
7. [Indicators of Compromise (IOCs)](#indicators-of-compromise-iocs)
8. [Attack Analysis](#attack-analysis)
9. [Detection and Mitigation](#detection-and-mitigation)
10. [Conclusion](#conclusion)
11. [Screenshots](#screenshots)
12. [Certification](#certification)
13. [Skills Demonstrated](#skills-demonstrated)
14. [Tools Used](#tools-used)

---

## Introduction

This case study documents a hands-on phishing email investigation completed as part of the **"The Planet's Prestige"** CTF challenge on **Blue Team Labs Online**. The objective was to simulate a real-world SOC (Security Operations Center) analyst workflow by examining a suspicious email flagged for potential phishing activity.

The investigation involved a full forensic review of the email including header analysis, authentication record verification, encoded attachment decoding, and malicious IP intelligence gathering. Each step mirrors the triage and analysis process used by SOC analysts when responding to phishing alerts in enterprise environments.

> **Scenario:** A suspicious email with the subject line _"A Hope to CoCanDa"_ was submitted for analysis. The task was to determine whether the email was malicious, identify the threat actor infrastructure, and document all indicators of compromise.

---

## Investigation Overview

| Field                  | Details                                            |
| ---------------------- | -------------------------------------------------- |
| **Investigation Type** | Phishing Email Forensics                           |
| **Platform**           | BlueTeam Labs Online                               |
| **Tools Used**         | MXToolbox, CyberChef, DomainTools                  |
| **Artifacts Analyzed** | Email headers, encoded attachment, IP address      |
| **Outcome**            | Confirmed phishing with potential malware delivery |

### Methodology

The investigation followed a structured triage approach:

1. **Header Analysis** — Extracted and analyzed full email headers to identify the true sender, routing path, and anomalies.
2. **Authentication Verification** — Evaluated SPF, DKIM, and DMARC records to assess sender legitimacy.
3. **Payload Decoding** — Decoded Base64-encoded attachment content to identify the file type.
4. **Threat Intelligence** — Performed IP reputation and geolocation lookups on the originating mail server.
5. **IOC Documentation** — Compiled all indicators of compromise for reporting and defensive use.

---

## Email Metadata Analysis

### Sender Details

| Field             | Value                     |
| ----------------- | ------------------------- |
| **From**          | `billjobs@microapple.com` |
| **Reply-To**      | `negeja3921@pashter.com`  |
| **Subject**       | `A Hope to CoCanDa`       |
| **Sender Domain** | `microapple.com`          |

### Analysis

The sender domain `microapple.com` is a clear **brand impersonation** attempt, designed to mimic Apple Inc. (`apple.com`) and potentially deceive recipients into believing the email originates from a legitimate technology company.

Key red flags identified at the metadata stage:

- **Domain spoofing:** `microapple.com` is not affiliated with Apple Inc. and appears crafted to exploit brand recognition.
- **Reply-To mismatch:** The `Reply-To` address (`negeja3921@pashter.com`) differs entirely from the sender domain. This is a classic phishing tactic to redirect victim replies to an attacker-controlled inbox while the sending domain appears more credible.
- **Unusual subject line:** `"A Hope to CoCanDa"` is semantically vague and does not correspond to any legitimate business communication pattern. Obfuscated or nonsensical subject lines are commonly used to bypass keyword-based spam filters.
- **Numeric identifier in reply address:** The string `negeja3921` suggests an auto-generated or disposable email address, commonly associated with throwaway accounts used in phishing infrastructure.

---

## Email Authentication Analysis

Email authentication protocols — **SPF**, **DKIM**, and **DMARC** — are used to verify that an email genuinely originates from the domain it claims to represent. Analysis of this email revealed failures across all three mechanisms.

### Results Summary

| Protocol  | Result     | Implication                                                             |
| --------- | ---------- | ----------------------------------------------------------------------- |
| **SPF**   | ❌ FAIL    | The sending IP is not authorized by `microapple.com`                    |
| **DKIM**  | ❌ FAIL    | Email content integrity cannot be verified; likely tampered or unsigned |
| **DMARC** | ⚠️ MISSING | No DMARC policy exists; no enforcement or reporting in place            |

### Detailed Breakdown

**SPF (Sender Policy Framework)**  
SPF failed, meaning the IP address that sent this email (`93.99.104.210`) is **not listed** in the SPF DNS record for `microapple.com`. This is a strong indicator that the email did not originate from an authorized mail server for that domain — a hallmark of spoofed or fraudulent sending infrastructure.

**DKIM (DomainKeys Identified Mail)**  
DKIM failed, indicating the email either **lacked a valid cryptographic signature** or the signature could not be verified. This means there is no assurance that the email content was not modified in transit, and the sender cannot be authenticated via this mechanism.

**DMARC (Domain-based Message Authentication, Reporting & Conformance)**  
No DMARC record was found for `microapple.com`. DMARC relies on both SPF and DKIM alignment — without it, there is no policy to quarantine or reject unauthenticated mail, and no reporting channel for abuse. The complete absence of DMARC suggests the domain was registered specifically for malicious use, with no intention of establishing legitimate email infrastructure.

> **Analyst Note:** Triple authentication failure (SPF + DKIM + no DMARC) is one of the strongest technical indicators that an email is fraudulent. Legitimate organizations universally implement at least SPF and DKIM for their mail-sending domains.

---

## Base64 Payload Analysis

### Decoding Process

The email contained an **attachment encoded in Base64**, a common obfuscation technique used by threat actors to conceal malicious file content from basic email security filters and human reviewers.

The encoded content was extracted and submitted to **CyberChef** using the `From Base64` operation to decode the raw bytes.

### Finding

Upon decoding, the output began with the byte sequence:

```
50 4B 03 04
```

This is the **magic bytes** signature for a **ZIP archive**, also known as the **PK signature** (named after Phil Katz, creator of the PKZIP format). This signature is universally recognized as the file header for `.zip`, `.docx`, `.xlsx`, `.jar`, and other ZIP-based container formats.

| Indicator          | Value                                                  |
| ------------------ | ------------------------------------------------------ |
| **Encoding**       | Base64                                                 |
| **Decoded Header** | `50 4B 03 04` (PK signature)                           |
| **File Type**      | ZIP archive (or ZIP-based container)                   |
| **Risk**           | High — ZIP files are frequently used to bundle malware |

### Significance

The use of Base64 encoding to disguise a ZIP file attachment is a well-documented phishing delivery technique. ZIP archives can contain:

- Executable payloads (`.exe`, `.bat`, `.ps1`)
- Macro-enabled Office documents (`.docm`, `.xlsm`)
- JavaScript droppers (`.js`, `.vbs`)
- LNK shortcut files pointing to remote malicious resources

The fact that the attachment was Base64-encoded rather than attached directly suggests a deliberate attempt to **evade automated email scanning** and deliver a potentially malicious payload to the victim.

---

## IP Address Investigation

### Target IP: `93.99.104.210`

The originating IP address of the email was investigated using **DomainTools** for geolocation, ASN attribution, and hosting context.

### Intelligence Summary

| Field            | Details                                                              |
| ---------------- | -------------------------------------------------------------------- |
| **IP Address**   | `93.99.104.210`                                                      |
| **Country**      | Latvia 🇱🇻                                                            |
| **ASN**          | Identified via DomainTools                                           |
| **Hosting Type** | Commercial hosting / VPS provider                                    |
| **Legitimacy**   | No association with Apple Inc. or any known legitimate mail provider |

### Analysis

The use of a **Latvian IP address** for an email impersonating an Apple-adjacent brand has no plausible legitimate explanation. Key observations:

- The IP belongs to a **commercial hosting or VPS provider**, which are commonly used by threat actors due to their ease of provisioning and relative anonymity.
- The geographic origin (Eastern Europe) is inconsistent with Apple's legitimate email infrastructure, which originates from Apple-owned or well-established cloud provider address spaces in the United States.
- The IP has **no established reputation** as a legitimate mail server, further corroborating the fraudulent nature of the email.

> **Analyst Note:** Legitimate transactional emails from major technology companies originate from verified, high-reputation IP ranges. An unknown IP in a jurisdiction unrelated to the impersonated brand is a reliable indicator of phishing infrastructure.

---

## Indicators of Compromise (IOCs)

The following IOCs were identified during this investigation and should be used for detection, blocking, and threat hunting purposes.

| IOC Type          | Value                        | Description                                      |
| ----------------- | ---------------------------- | ------------------------------------------------ |
| **IP Address**    | `93.99.104.210`              | Originating mail server IP — Latvia              |
| **Domain**        | `microapple.com`             | Sender domain — Apple brand impersonation        |
| **Domain**        | `pashter.com`                | Reply-To domain — attacker-controlled inbox      |
| **Email Address** | `billjobs@microapple.com`    | Sender email address                             |
| **Email Address** | `negeja3921@pashter.com`     | Reply-To address — attacker-controlled           |
| **Subject Line**  | `A Hope to CoCanDa`          | Phishing email subject — used for filter evasion |
| **File Type**     | ZIP Archive (Base64 encoded) | Attachment — potential malware delivery vehicle  |

### MITRE ATT&CK Mapping

| Technique ID | Technique Name                     | Observed Behavior                             |
| ------------ | ---------------------------------- | --------------------------------------------- |
| T1566.001    | Phishing: Spearphishing Attachment | Malicious ZIP attachment delivered via email  |
| T1036        | Masquerading                       | Domain impersonating Apple (`microapple.com`) |
| T1027        | Obfuscated Files or Information    | Attachment encoded in Base64                  |
| T1071.003    | Application Layer Protocol: Mail   | Email used as initial access vector           |

---

## Attack Analysis

### Threat Actor Objective

Based on the evidence gathered, this email represents a **phishing attack with a malware delivery component**. The threat actor's likely objectives were:

1. **Initial Access via Social Engineering**  
   The email impersonates a trusted Apple-affiliated entity to establish credibility. The vague but intriguing subject line (_"A Hope to CoCanDa"_) may be designed to trigger curiosity-driven opens, bypassing the recipient's skepticism.

2. **Credential Harvesting or Malware Execution**  
   The Base64-encoded ZIP attachment is the primary delivery mechanism. Depending on the contents of the archive, the attacker may have been attempting to:

   - Execute a **dropper or loader** to establish persistence
   - Deliver a **Remote Access Trojan (RAT)** or **infostealer**
   - Direct victims to a **credential phishing page** via a URL within the attachment

3. **Reply-To Redirection**  
   The mismatch between the `From` and `Reply-To` addresses serves a dual purpose: it routes any victim responses to an attacker-controlled mailbox (`negeja3921@pashter.com`) while keeping the sending domain appearing more contextually relevant to the impersonated brand.

### Attack Chain

```
[Attacker sends email from 93.99.104.210]
        │
        ▼
[Spoofed domain: microapple.com | SPF/DKIM/DMARC failures]
        │
        ▼
[Victim receives email — persuaded by Apple brand impersonation]
        │
        ▼
[Victim opens Base64-encoded ZIP attachment]
        │
        ▼
[ZIP payload executes — potential malware installation or credential theft]
        │
        ▼
[Any victim replies routed to attacker inbox: negeja3921@pashter.com]
```

---

## Detection and Mitigation

### Recommended Defensive Actions

**Immediate Response (Tactical)**

- 🔴 **Block IP** `93.99.104.210` at the email gateway and perimeter firewall
- 🔴 **Block domains** `microapple.com` and `pashter.com` in DNS filtering and email security platforms
- 🔴 **Quarantine** any emails matching the subject line `"A Hope to CoCanDa"` across the mail environment
- 🔴 **Alert** end users who may have received or interacted with this email

**Email Security Controls (Strategic)**

| Control                   | Recommendation                                                                   |
| ------------------------- | -------------------------------------------------------------------------------- |
| **SPF Enforcement**       | Configure email gateway to quarantine or reject SPF-failing inbound mail         |
| **DKIM Verification**     | Enforce DKIM signature validation; flag unsigned or unverifiable messages        |
| **DMARC Policy**          | Reject unauthenticated mail from impersonated domains (`p=reject`)               |
| **Attachment Sandboxing** | Detonate ZIP and encoded attachments in a sandboxed environment before delivery  |
| **Base64 Scanning**       | Configure DLP/email security to scan and decode Base64-encoded attachments       |
| **Reply-To Alerting**     | Flag emails where the `Reply-To` domain differs significantly from `From` domain |

**User Awareness**

- Train users to verify sender domains carefully — `microapple.com` ≠ `apple.com`
- Educate staff on the risk of opening unexpected attachments, even from apparently familiar senders
- Establish a clear process for reporting suspicious emails to the SOC

---

## Conclusion

This investigation confirmed that the email submitted for analysis is a **phishing attack** exhibiting multiple, corroborating indicators of malicious intent:

- ✅ **Brand impersonation** via a fraudulent sender domain (`microapple.com`)
- ✅ **Triple authentication failure** — SPF failed, DKIM failed, DMARC absent
- ✅ **Reply-To hijacking** to redirect victim communications to attacker infrastructure
- ✅ **Obfuscated malicious attachment** — Base64-encoded ZIP file indicating payload delivery intent
- ✅ **Suspicious originating infrastructure** — Commercial VPS in Latvia with no affiliation to the impersonated brand

The combination of brand impersonation, authentication failures, encoded payload delivery, and attacker-controlled reply infrastructure represents a **well-structured, multi-layered phishing campaign**. The email should be classified as **malicious**, and all associated IOCs should be immediately actioned across relevant security controls.

---

## Screenshots

> 📌 _Replace each placeholder below with your actual investigation screenshots._

### Email Header Analysis — MXToolbox

![Email Header Analysis](./screenshots/01-email-header-mxtoolbox.jpg)

> _Caption: Full email header analysis performed in MXToolbox, showing routing hops, sender IP, and header anomalies._

---

### Base64 Decoding — CyberChef

![CyberChef Base64 Decode](./screenshots/02-cyberchef-base64-decode.jpg)

> _Caption: CyberChef `From Base64` operation applied to attachment content, revealing the ZIP file PK magic bytes signature._

---

### IP Intelligence Lookup — DomainTools

![DomainTools IP Lookup](./screenshots/03-domaintools-ip-lookup.jpg)

> _Caption: DomainTools investigation of IP address `93.99.104.210`, showing geolocation (Latvia), ASN, and hosting details._

---

### Email Authentication Results — MXToolbox

![MXToolbox Authentication Results](./screenshots/04-mxtoolbox-auth-results.jpg)

> _Caption: MXToolbox results confirming SPF failure, DKIM failure, and missing DMARC record for `microapple.com`._

---

## Certification

> 📌 _Insert a screenshot of your certificate below, or link directly to the verification page._

![BlueTeam Labs Certificate](./screenshots/certificate-btlo.jpg)

| Field                | Details                                                                               |
| -------------------- | ------------------------------------------------------------------------------------- |
| **Recipient**        | Thembinkosi Madiba                                                                    |
| **Challenge**        | The Planet's Prestige                                                                 |
| **Platform**         | BlueTeam Labs Online                                                                  |
| **Category**         | CTF                                                                                   |
| **Difficulty**       | Easy                                                                                  |
| **Points Awarded**   | 10                                                                                    |
| **Completed**        | March 12, 2026                                                                        |
| **Verification URL** | [View Certificate](https://blueteamlabs.online/achievement/share/challenge/149863/10) |
| **Status**           | ✅ Completed                                                                          |

---

## Skills Demonstrated

| Skill                                    | Description                                                                                    |
| ---------------------------------------- | ---------------------------------------------------------------------------------------------- |
| **Email Header Analysis**                | Extracted and interpreted full email headers to trace the delivery path and identify anomalies |
| **Phishing Detection**                   | Identified brand impersonation, Reply-To mismatches, and obfuscated subject lines              |
| **Email Authentication Analysis**        | Evaluated SPF, DKIM, and DMARC records to assess sender legitimacy                             |
| **Base64 Decoding**                      | Used CyberChef to decode encoded attachment content and identify file type via magic bytes     |
| **Magic Byte / File Signature Analysis** | Identified ZIP file header (`50 4B 03 04`) from raw decoded bytes                              |
| **Threat Intelligence Investigation**    | Conducted IP reputation, geolocation, and ASN analysis using DomainTools                       |
| **IOC Identification & Documentation**   | Compiled structured IOC table with IPs, domains, email addresses, and file indicators          |
| **MITRE ATT&CK Mapping**                 | Mapped observed attacker behaviors to relevant ATT&CK technique IDs                            |
| **Defensive Recommendations**            | Produced actionable detection and mitigation guidance for SOC teams                            |

---

## Tools Used

| Tool                     | Purpose                                           | Link                                                         |
| ------------------------ | ------------------------------------------------- | ------------------------------------------------------------ |
| **MXToolbox**            | Email header analysis and authentication checks   | [mxtoolbox.com](https://mxtoolbox.com)                       |
| **CyberChef**            | Base64 decoding and file signature identification | [gchq.github.io/CyberChef](https://gchq.github.io/CyberChef) |
| **DomainTools**          | IP address intelligence and geolocation lookup    | [domaintools.com](https://domaintools.com)                   |
| **BlueTeam Labs Online** | Phishing investigation challenge platform         | [blueteamlabs.online](https://blueteamlabs.online)           |

---

<div align="center">

**📁 Part of my Cybersecurity Portfolio**  
_Documenting real-world blue team investigations, threat analysis, and SOC workflows._

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=flat&logo=linkedin)](https://linkedin.com/in/YOUR-PROFILE)
[![GitHub](https://img.shields.io/badge/GitHub-Portfolio-black?style=flat&logo=github)](https://github.com/YOUR-USERNAME)

</div>
