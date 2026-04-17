# 🔒 macOS Security Audit Script

A comprehensive, interactive security audit script for macOS — built from a real-world audit of a MacBook Pro (Apple Silicon). Covers all major attack surfaces including persistence mechanisms, user accounts, network security, installed software, and filesystem integrity.

---

## Features

- ✅ **7 audit phases** covering the full macOS security surface
- 🎨 **Colored terminal output** — Pass / Warn / Fail at a glance
- 📄 **Markdown report generation** — saved to `~/security-audit-reports/`
- 🔧 **Optional fixes** — prompted interactively, never applied silently
- 🍎 **Apple Silicon native** — tested on macOS 15+ with Secure Boot / SIP verification
- 🔑 **No third-party dependencies** — pure bash, uses only built-in macOS tools
- 📋 **Customizable allowlist** — add your own software vendors before running

---

## What Gets Audited

| Phase | Area | Key Checks |
|-------|------|------------|
| 1 | System Baseline | OS version, install date, user accounts, admin group |
| 2 | Core Security Features | SIP, Gatekeeper, FileVault, Firewall, Remote Login |
| 3 | Persistence Mechanisms | LaunchAgents, LaunchDaemons, StartupItems, Cron, PrivilegedHelperTools |
| 4 | User Account Audit | Sudoers, SSH authorized keys, drop-in configs |
| 5 | Network Security | Hosts file, DNS servers, proxy settings, listening ports |
| 6 | Installed Software | Kernel extensions, Gatekeeper app assessment, Homebrew audit |
| 7 | Filesystem Integrity | World-writable files, SUID binaries, /tmp, hidden files |

---

## Requirements

- macOS 13 (Ventura) or later
- Apple Silicon or Intel Mac
- `sudo` access (required for full audit)
- Bash 3.2+ (included with macOS)

---

## Installation

```bash
# Clone the repository
git clone https://github.com/black-cat-ops/mac-security-audit.git
cd mac-security-audit

# Make the script executable
chmod +x mac_security_audit.sh
```

---

## Usage

```bash
# Run the full audit (sudo required)
sudo bash mac_security_audit.sh
```

The script will:
1. Run all 7 audit phases with colored output
2. Prompt you before applying any fixes
3. Save a full markdown report to `~/security-audit-reports/`

---

## Sample Output

```
============================================================
  Phase 2 — Core Security Features
============================================================

  [CHECK] System Integrity Protection (SIP)
  [PASS]  SIP is enabled
  [CHECK] Gatekeeper
  [PASS]  Gatekeeper is enabled
  [CHECK] FileVault disk encryption
  [PASS]  FileVault is On
  [CHECK] Application Firewall
  [PASS]  Firewall is enabled
  [CHECK] Remote Login (SSH)
  [PASS]  Remote Login is Off
```

See [SAMPLE_REPORT.md](SAMPLE_REPORT.md) for a full example report output.

---

## Fix Behavior

When an issue is found that can be remediated automatically, the script will prompt:

```
  [FIX AVAILABLE] Re-enable Gatekeeper now?
  Apply fix? (y/n):
```

Fixes are **never applied silently**. You are always in control.

### Auto-fixable Issues
| Issue | Fix Applied |
|-------|-------------|
| Gatekeeper disabled | `spctl --master-enable` |
| Firewall disabled | `socketfilterfw --setglobalstate on` |
| Remote Login enabled | `systemsetup -setremotelogin off` |

### Manual Remediation Required
| Issue | How to Fix |
|-------|-----------|
| SIP disabled | Boot into Recovery Mode → Terminal → `csrutil enable` |
| FileVault off | System Settings → Privacy & Security → FileVault |
| Unknown LaunchAgent/Daemon | Investigate binary, verify signature with `codesign -dvvv` |
| Unexpected SUID binary | Investigate with `codesign` and `file` commands |

---

## Report Output

Reports are saved to:
```
~/security-audit-reports/security_audit_YYYY-MM-DD_HH-MM-SS.md
```

Each report includes:
- Per-phase results with pass/warn/fail status
- System metadata (hostname, macOS version, date)
- Summary table with total issues and fixes applied

---

## Customization

Before running, open `mac_security_audit.sh` and add your own software to the `KNOWN_AGENTS` allowlist in Phase 3. Any LaunchAgent or LaunchDaemon not matching the list will be flagged as unknown.

```bash
# ADD YOUR OWN SOFTWARE BELOW THIS LINE
# Example:
"com.mycompany"
"com.mytool"
```

Common entries you might want to add depending on your setup:
- Corporate VPN: `"com.cisco.anyconnect"`, `"com.paloaltonetworks"`
- Password managers: `"com.1password"`, `"com.dashlane"`
- Cloud storage: `"com.box"`, `"com.carbonite"`
- MDM agents: `"com.jamf"`, `"com.kandji"`, `"com.mosyle"`

---

## Security Considerations

- This script requires `sudo` — always review scripts before running them with elevated privileges
- The script never transmits data externally
- No third-party tools or network requests are made
- All fixes are reversible and prompted before application

---

## Recommended Companion Tools

These free tools complement this script for deeper analysis:

| Tool | Purpose | Source |
|------|---------|--------|
| **KnockKnock** | Visual persistence scanner | objective-see.org |
| **BlockBlock** | Real-time persistence monitor | objective-see.org |
| **LuLu** | Open source outbound firewall | objective-see.org |
| **TaskExplorer** | Process inspector with VirusTotal | objective-see.org |
| **Malwarebytes** | Malware scanner | malwarebytes.com |

---

## Roadmap

- [ ] MDM enrollment detection
- [ ] Browser extension auditing (Chrome/Brave/Firefox)
- [ ] Time Machine backup verification
- [ ] Automated codesign verification for all PrivilegedHelperTools
- [ ] HTML report output option
- [ ] Slack/email report delivery

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on contributing to this project.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Acknowledgements

Built from a real-world macOS security audit. Inspired by the excellent work of [Objective-See](https://objective-see.org) and the macOS security research community.

