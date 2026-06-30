# FortiGate Hardening Compliance App

**Version:** Beta 1.0  
**Status:** First public iteration  
**Platform:** macOS and Linux  
**License:** Free to use. Not for sale or resale.

## Overview

FortiGate Hardening Compliance App is a lightweight local web application that connects to a live FortiGate device using the FortiOS REST API and validates selected hardening controls based on Fortinet best-practice guidance.

The app prompts for the FortiGate IP address or FQDN, HTTPS/API port, VDOM, firmware baseline, and REST API token. It then performs read-only API `GET` requests and generates an HTML compliance report showing which controls pass, fail, or require review.

This first beta release focuses on practical, machine-checkable hardening items such as administrator access posture, management exposure, strong cryptographic settings, FortiGuard status, DoS policy presence, logging configuration, and related FortiOS hardening checks.

## Supported FortiOS Baselines

The app includes a baseline selector for:

- FortiOS 8.0
- FortiOS 7.6
- FortiOS 7.4

Reference hardening guides:

- FortiOS 8.0 Hardening: https://docs.fortinet.com/document/fortigate/8.0.0/best-practices/555436/hardening
- FortiOS 7.6 Hardening: https://docs.fortinet.com/document/fortigate/7.6.0/best-practices/555436
- FortiOS 7.4 Hardening: https://docs.fortinet.com/document/fortigate/7.4.0/best-practices/555436

## Features

- Local web interface using Flask
- Read-only REST API validation
- FortiGate IP/FQDN prompt
- REST API token prompt
- Optional VDOM selection
- Firmware baseline selection for 8.0, 7.6, and 7.4
- HTML compliance report generation
- Control results by category
- PASS, FAIL, and REVIEW status indicators
- Recommendations for failed or review-required checks
- Evidence captured from FortiGate API responses where available
- Designed to run locally on macOS or Linux

## Beta 1.0 Scope

This is the first beta iteration. It is intended for lab testing, internal validation, and early feedback.

The app currently focuses on controls that can be validated through FortiOS REST API `GET` calls. Some Fortinet hardening recommendations require manual validation, operational evidence, external feeds, or business-context review. Those controls may appear as `REVIEW` or may be excluded from automated scoring in this beta.

Examples of controls that may require manual review:

- Physical security of the appliance
- Penetration testing evidence
- PSIRT monitoring process
- Backup storage handling
- Exception approvals
- Whether a local break-glass account is formally approved
- Whether specific firewall policies are business-justified

## Requirements

### Operating System

The app is designed to run on:

- macOS
- Linux

It has not been tested on Windows in this beta release.

### Software Requirements

Install the following before running the app:

- Python 3.9 or later
- `pip`
- Python virtual environment support

On macOS, Python can be installed using Homebrew:

```bash
brew install python
```

On Ubuntu/Debian Linux:

```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv
```

On RHEL/CentOS/Fedora-based systems:

```bash
sudo dnf install python3 python3-pip
```

## FortiGate Requirements

You need access to a FortiGate device running one of the supported firmware families:

- FortiOS 8.0.x
- FortiOS 7.6.x
- FortiOS 7.4.x

The FortiGate must be reachable from the machine running this app over HTTPS.

You must create a REST API administrator on the FortiGate with read-only permissions. Do not use a full `super_admin` account unless absolutely required for testing.

Recommended API administrator posture:

- Read-only access profile
- Trusted host restriction
- Token-based authentication
- Dedicated API user for this scanner
- Access only from the machine or subnet running the scanner

The app sends the API token using the HTTP header:

```text
Authorization: Bearer <token>
```

## Installation

Download or clone this repository:

```bash
git clone https://github.com/<your-username>/<your-repo-name>.git
cd <your-repo-name>
```

Create a Python virtual environment:

```bash
python3 -m venv .venv
```

Activate the virtual environment:

```bash
source .venv/bin/activate
```

Install the required Python packages:

```bash
pip install -r requirements.txt
```

## Running the App

Start the app:

```bash
python app.py
```

Open your browser and go to:

```text
http://127.0.0.1:5050
```

Complete the scan form:

1. Select the FortiOS hardening baseline:
   - FortiOS 8.0
   - FortiOS 7.6
   - FortiOS 7.4
2. Enter the FortiGate IP address or FQDN.
3. Enter the FortiGate HTTPS/API port. The default is usually `443`.
4. Enter the VDOM name if required. The default is usually `root`.
5. Enter the REST API token.
6. Choose whether to verify the TLS certificate.
7. Run the scan.

The app will connect to the FortiGate using read-only API requests and generate an HTML report.

## Running the App Again Later

After the app has been installed once, you only need to activate the environment and start it again.

```bash
cd <your-repo-name>
source .venv/bin/activate
python app.py
```

Then open:

```text
http://127.0.0.1:5050
```

To stop the app, press:

```text
Ctrl + C
```

## Optional Launcher Script

You can create a small launcher script to make startup easier.

Create a file named `run.sh`:

```bash
nano run.sh
```

Paste the following:

```bash
#!/bin/bash

cd "$(dirname "$0")"
source .venv/bin/activate
python app.py
```

Save the file, then make it executable:

```bash
chmod +x run.sh
```

Now you can run the app with:

```bash
./run.sh
```

## Optional Shell Alias

You can also create a shell alias.

For macOS using Zsh:

```bash
nano ~/.zshrc
```

For Linux using Bash:

```bash
nano ~/.bashrc
```

Add this line, adjusting the path to your app folder:

```bash
alias fgt-hardening='cd ~/fortigate_hardening_app && ./run.sh'
```

Reload your shell profile:

```bash
source ~/.zshrc
```

or:

```bash
source ~/.bashrc
```

Then run the app anytime with:

```bash
fgt-hardening
```

## Report Output

The HTML report includes:

- Device information
- Selected hardening baseline
- Scan timestamp
- Control category
- Control ID
- Control description
- Compliance status
- Severity
- Evidence
- Recommendation

Statuses used by the app:

| Status | Meaning |
|---|---|
| PASS | The setting appears to comply with the selected baseline. |
| FAIL | The setting does not appear to comply with the selected baseline. |
| REVIEW | The app could not fully validate the control or the control requires human review. |

## Important Security Notes

This app is intended to run locally. Do not expose it directly to untrusted networks.

Recommended practices:

- Run it from a trusted workstation.
- Use a read-only FortiGate API token.
- Restrict the FortiGate API admin trusted hosts.
- Do not commit API tokens, reports, or sensitive configuration evidence to GitHub.
- Do not share generated reports publicly unless they have been reviewed and sanitized.
- Treat reports as sensitive security documents.

## Limitations

This beta release is not a replacement for a full security audit.

Known limitations:

- Not all Fortinet hardening controls can be validated automatically.
- Some checks depend on API permissions available to the read-only token.
- Some checks may require manual validation or exception handling.
- Some recommendations may need to be adapted to the customer environment.
- The app has not been tested across every FortiGate model, VDOM mode, HA mode, or FortiOS patch level.
- The app does not currently perform active penetration testing.
- The app does not modify FortiGate configuration.

## Troubleshooting

### The app cannot connect to the FortiGate

Check:

- The FortiGate IP/FQDN is correct.
- The HTTPS/API port is correct.
- Your workstation can reach the FortiGate.
- Administrative HTTPS access is allowed from your source IP.
- The API admin trusted host allows your source IP.
- The REST API token is valid.

### TLS certificate errors

If the FortiGate uses a self-signed certificate, certificate verification may fail.

For lab testing, you may disable TLS verification in the app form. For production use, it is better to install and use a trusted certificate on the FortiGate.

### Some checks show REVIEW

`REVIEW` means the app could not fully confirm the control using API data alone, or the item requires human judgment.

Examples:

- Physical security
- Business justification
- Break-glass account exceptions
- Backup handling
- PSIRT monitoring process

### API permission errors

The read-only API profile may not have access to every endpoint required by the scanner.

Check the REST API administrator profile and confirm that the token has sufficient read permissions for:

- System settings
- Administrator settings
- Interfaces
- Local-in policy
- Firewall policy
- DoS policy
- Logging
- FortiGuard status where available

## Disclaimer

This project is an independent tool and is not an official Fortinet product. Fortinet, FortiGate, FortiOS, FortiGuard, FortiAnalyzer, and related names are trademarks or registered trademarks of Fortinet, Inc.

Use this app at your own risk. Always validate findings before making security, compliance, or production decisions.

## License

This project is provided as free-to-use software.

You may:

- Use it for personal, internal, lab, educational, and customer assessment purposes.
- Modify it for your own internal use.
- Share it freely with proper attribution.

You may not:

- Sell this app.
- Resell this app.
- Repackage this app as a paid product.
- Include this app in a commercial offering without written permission from the author.
- Remove attribution or present the original work as your own.

Suggested license label:

```text
Free Use License - No Sale or Resale
```

For stronger legal enforcement, add a dedicated `LICENSE` file reviewed by legal counsel.

## Roadmap Ideas

Potential future improvements:

- Export to CSV and JSON
- Add PDF report generation
- Add severity scoring
- Add executive summary
- Add remediation CLI snippets
- Add multi-FortiGate scan support
- Add FortiManager support
- Add HA awareness
- Add more granular VDOM handling
- Add exception workflow
- Add control mapping to CIS, PCI DSS, and Fortinet Security Rating
- Add historical scan comparison

## Contributing

This is Beta 1.0 and feedback is welcome.

Suggested feedback areas:

- False positives
- False negatives
- Missing controls
- FortiOS version differences
- API endpoint compatibility
- Report formatting
- Additional hardening recommendations

## Author

Created as a first beta iteration for FortiGate hardening validation using FortiOS REST API read-only checks.
