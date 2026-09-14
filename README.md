# Email Header Analyzer Toolkit

A beginner-friendly Python toolkit for analyzing suspicious email headers.

## What it checks

- 🛡️ SPF results
- 🔐 DKIM results
- ✅ DMARC results
- 🌐 `Received` server chain
- 📩 From / Return-Path / Reply-To / Sender
- 🕒 Message date, subject and Message-ID
- 🌍 IP addresses found in routing headers
- 🔎 Optional reverse DNS lookups
- ⚠️ Basic header consistency warnings
- 📄 JSON report export

## Important: finding where an email "actually came from"

Email headers can show the mail servers and IP addresses involved in delivery. They do **not** always prove the physical device or person that originally sent the email.

The most useful evidence is usually the `Received:` chain. In a normal message, the headers are displayed newest-first, so the oldest `Received:` entry is often closest to the originating mail system.

However, attackers can forge some headers. For investigations, give the most weight to headers added by mail infrastructure you trust (for example, your own Microsoft 365, Google Workspace, Exchange, or mail gateway).

Also remember:

- A sending IP can belong to a cloud provider, VPN, relay, or email service.
- SPF authenticates the envelope sender/domain relationship, not the human sender.
- DKIM validates a cryptographic signature from a domain.
- DMARC evaluates alignment between the visible From domain and authenticated domains.
- A `pass` result does not mean the message is safe; it means the relevant authentication check passed.

## Requirements

Python 3.9+.

The main analyzer uses Python's standard library, so no third-party package is required.

## Installation

### Windows

```powershell
py -3 --version
```

Then run:

```powershell
py email_header_analyzer.py suspicious.eml
```

### Linux / Kali / Ubuntu

```bash
python3 --version
python3 email_header_analyzer.py suspicious.eml
```

## Usage

Analyze a complete `.eml` file:

```bash
python3 email_header_analyzer.py suspicious.eml
```

Analyze copied raw headers:

```bash
python3 email_header_analyzer.py --headers-only headers.txt
```

Save a JSON report:

```bash
python3 email_header_analyzer.py suspicious.eml --json report.json
```

Also perform reverse-DNS lookups:

```bash
python3 email_header_analyzer.py suspicious.eml --dns
```

You can combine them:

```bash
python3 email_header_analyzer.py suspicious.eml --dns --json report.json
```

## Getting raw headers

### Gmail

Open the email → three dots → **Show original** → copy the original headers or download the original message.

### Microsoft Outlook / Microsoft 365

Use the message's **View source / View message details / Internet headers** option available in your Outlook version.

When possible, save the complete message as `.eml` rather than copying only part of the header.

## How to read the result

### 1. From

Example:

```text
From: "Example" <billing@example.com>
```

This is the visible sender address. It can be spoofed unless authentication and trusted mail infrastructure support it.

### 2. Return-Path

The Return-Path is related to the SMTP envelope sender and is important when checking SPF and bounce handling.

### 3. Received

Example:

```text
Received: from mail.example.net (mail.example.net [203.0.113.20])
        by mx.yourcompany.com ...
```

The analyzer lists each `Received` header as a hop.

Do **not** automatically assume that the first IP you see is the attacker's IP. Work backward through the chain and determine which headers were inserted by trusted systems.

### 4. SPF

Typical results:

```text
SPF: PASS
SPF: FAIL
SPF: SOFTFAIL
SPF: NEUTRAL
SPF: NONE
```

SPF checks whether the sending infrastructure is authorized for the envelope sender domain.

### 5. DKIM

DKIM uses a cryptographic signature. A `DKIM=PASS` result can provide evidence that the signed content/header set was authenticated by the signing domain and was not altered in a way that breaks the signature.

### 6. DMARC

DMARC connects the visible `From:` domain with SPF/DKIM authentication and alignment.

A DMARC pass is useful evidence, but it does not by itself prove that the sender is trustworthy.

## Investigation workflow

For a suspicious email:

1. Preserve the original `.eml`.
2. Do not edit the original evidence file.
3. Run the analyzer.
4. Review the `Received` chain from newest to oldest.
5. Identify the earliest trusted mail gateway/server.
6. Compare the visible `From` domain with Return-Path.
7. Review SPF, DKIM and DMARC.
8. Check suspicious IPs and domains using your organization's approved threat-intelligence tools.
9. Export the JSON report.
10. Correlate the result with mail-server, Microsoft 365/Google Workspace, firewall, proxy, or SIEM logs.

## Evidence handling

For a real incident, keep:

- Original `.eml`
- SHA-256 hash of the original file
- Analyzer JSON output
- Date/time of analysis
- Analyst name/ID
- Relevant SIEM/mail-gateway logs

Never modify the original evidence.

## Limitations

This is a defensive analysis tool. It parses the information available in the message; it does not perform mailbox compromise, credential testing, or unauthorized access.

The tool cannot guarantee attribution to a person or physical device. Header analysis should be combined with trusted mail-system logs and other evidence.

## Project structure

```text
email-header-analyzer/
├── email_header_analyzer.py
├── README.md
├── requirements.txt
└── samples/
    └── sample_headers.txt
```
