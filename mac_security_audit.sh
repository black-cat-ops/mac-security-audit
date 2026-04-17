#!/bin/bash
# =============================================================================
# macOS Security Audit Script
# Author: Jen
# Description: Comprehensive macOS security audit covering persistence,
#              users, network, software, and filesystem integrity.
#              Outputs colored terminal results + a markdown report.
# =============================================================================

VERSION="1.0.2"
REPORT_DIR="$HOME/security-audit-reports"
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
REPORT_FILE="$REPORT_DIR/security_audit_$TIMESTAMP.md"
ISSUES_FOUND=0
FIXES_APPLIED=0

# =============================================================================
# COLORS
# =============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# =============================================================================
# HELPERS
# =============================================================================
print_header() {
    echo ""
    echo -e "${BOLD}${BLUE}============================================================${RESET}"
    echo -e "${BOLD}${BLUE}  $1${RESET}"
    echo -e "${BOLD}${BLUE}============================================================${RESET}"
    echo ""
    echo -e "\n## $1\n" >> "$REPORT_FILE"
}

print_check() {
    echo -e "  ${CYAN}[CHECK]${RESET} $1"
    echo "- **CHECK:** $1" >> "$REPORT_FILE"
}

print_pass() {
    echo -e "  ${GREEN}[PASS]${RESET}  $1"
    echo "  - ✅ PASS: $1" >> "$REPORT_FILE"
}

print_warn() {
    echo -e "  ${YELLOW}[WARN]${RESET}  $1"
    echo "  - ⚠️ WARN: $1" >> "$REPORT_FILE"
    ((ISSUES_FOUND++))
}

print_fail() {
    echo -e "  ${RED}[FAIL]${RESET}  $1"
    echo "  - ❌ FAIL: $1" >> "$REPORT_FILE"
    ((ISSUES_FOUND++))
}

print_info() {
    echo -e "  ${BOLD}[INFO]${RESET}  $1"
    echo "  - ℹ️ INFO: $1" >> "$REPORT_FILE"
}

ask_fix() {
    echo ""
    echo -e "  ${YELLOW}[FIX AVAILABLE]${RESET} $1"
    echo -e "  ${BOLD}Apply fix? (y/n):${RESET} " 
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        return 0
    fi
    return 1
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}This script must be run with sudo.${RESET}"
        echo "Usage: sudo bash mac_security_audit.sh"
        exit 1
    fi
}

init_report() {
    mkdir -p "$REPORT_DIR"
    cat > "$REPORT_FILE" <<EOF
# macOS Security Audit Report
**Date:** $(date)
**Hostname:** $(hostname)
**macOS Version:** $(sw_vers -productVersion)
**Script Version:** $VERSION

---
EOF
    echo -e "${BOLD}${GREEN}macOS Security Audit v$VERSION${RESET}"
    echo -e "${BOLD}Report will be saved to:${RESET} $REPORT_FILE"
    echo ""
}

# =============================================================================
# PHASE 1 — BASELINE
# =============================================================================
phase1_baseline() {
    print_header "Phase 1 — System Baseline"

    # macOS Version
    print_check "macOS version"
    OS_VERSION=$(sw_vers -productVersion)
    print_info "macOS $OS_VERSION (Build: $(sw_vers -buildVersion))"

    # OS Install Date
    print_check "OS install/setup date"
    SETUP_DATE=$(stat -f "%Sm" /private/var/db/.AppleSetupDone 2>/dev/null)
    print_info "Setup completed: $SETUP_DATE"

    # User accounts
    print_check "User accounts (UID >= 500)"
    USERS=$(dscl . list /Users UniqueID | awk '$2 >= 500')
    while IFS= read -r line; do
        USER=$(echo "$line" | awk '{print $1}')
        UID_VAL=$(echo "$line" | awk '{print $2}')
        # Flag anything that isn't a known system account pattern
        if [[ "$USER" == *"malwarebytes"* ]] || [[ "$USER" == *"nobody"* ]]; then
            print_pass "System service account: $USER (UID: $UID_VAL)"
        else
            print_info "Human account found: $USER (UID: $UID_VAL) — verify this is expected"
        fi
    done <<< "$USERS"

    # Admin group members
    print_check "Admin group membership"
    ADMINS=$(dscl . read /Groups/admin GroupMembership 2>/dev/null | sed 's/GroupMembership: //')
    print_info "Admin members: $ADMINS"
    ADMIN_COUNT=$(echo "$ADMINS" | wc -w | tr -d ' ')
    if [[ "$ADMIN_COUNT" -gt 2 ]]; then
        print_warn "More than 2 admin accounts detected — review carefully: $ADMINS"
    else
        print_pass "Admin group looks normal: $ADMINS"
    fi
}

# =============================================================================
# PHASE 2 — CORE SECURITY FEATURES
# =============================================================================
phase2_security_features() {
    print_header "Phase 2 — Core Security Features"

    # SIP
    print_check "System Integrity Protection (SIP)"
    SIP=$(csrutil status 2>/dev/null)
    if echo "$SIP" | grep -q "enabled"; then
        print_pass "SIP is enabled"
    else
        print_fail "SIP is DISABLED — critical security risk"
        if ask_fix "SIP must be re-enabled in Recovery Mode (csrutil enable). Open instructions?"; then
            echo -e "  ${CYAN}Boot into Recovery Mode (hold Power on Apple Silicon) → Utilities → Terminal → csrutil enable${RESET}"
        fi
    fi

    # Gatekeeper
    print_check "Gatekeeper"
    GK=$(spctl --status 2>/dev/null)
    if echo "$GK" | grep -q "enabled"; then
        print_pass "Gatekeeper is enabled"
    else
        print_fail "Gatekeeper is DISABLED"
        if ask_fix "Re-enable Gatekeeper now?"; then
            spctl --master-enable
            print_pass "Gatekeeper re-enabled"
            ((FIXES_APPLIED++))
        fi
    fi

    # FileVault
    print_check "FileVault disk encryption"
    FV=$(fdesetup status 2>/dev/null)
    if echo "$FV" | grep -q "On"; then
        print_pass "FileVault is On"
    else
        print_fail "FileVault is OFF — disk is unencrypted"
        print_info "Enable via: System Settings → Privacy & Security → FileVault"
    fi

    # Firewall
    print_check "Application Firewall"
    FW=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)
    if echo "$FW" | grep -q "enabled"; then
        print_pass "Firewall is enabled"
    else
        print_warn "Firewall is DISABLED"
        if ask_fix "Enable firewall now?"; then
            /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
            print_pass "Firewall enabled"
            ((FIXES_APPLIED++))
        fi
    fi

    # Remote Login (SSH)
    print_check "Remote Login (SSH)"
    SSH_STATUS=$(systemsetup -getremotelogin 2>/dev/null)
    if echo "$SSH_STATUS" | grep -q "Off"; then
        print_pass "Remote Login is Off"
    else
        print_warn "Remote Login is ON — SSH is accepting connections"
        if ask_fix "Disable Remote Login now?"; then
            systemsetup -setremotelogin off
            print_pass "Remote Login disabled"
            ((FIXES_APPLIED++))
        fi
    fi
}

# =============================================================================
# PHASE 3 — PERSISTENCE MECHANISMS
# =============================================================================
phase3_persistence() {
    print_header "Phase 3 — Persistence Mechanisms"

    # =============================================================================
    # KNOWN AGENTS ALLOWLIST
    # This list covers the most common macOS system and vendor LaunchAgents/Daemons.
    # Add your own software prefixes below before running in your environment.
    # Format: "com.vendorname" — prefix matched, so "com.apple" covers all Apple agents.
    # =============================================================================
    KNOWN_AGENTS=(
        # Apple system agents — always expected
        "com.apple"
        "org.apple"

        # Common productivity & collaboration
        "com.microsoft"
        "com.adobe"
        "com.google"
        "us.zoom"
        "com.dropbox"
        "com.slack"

        # Security software
        "com.malwarebytes"
        "com.crowdstrike"
        "com.carbonblack"
        "com.jamf"
        "com.kandji"

        # Developer tools
        "com.docker"
        "org.wireshark"
        "com.vagrant"

        # Browsers
        "com.brave"
        "org.mozilla"
        "com.google.chrome"

        # VPN clients (remove any you don't use)
        "com.nordvpn"
        "com.expressvpn"
        "com.privateinternetaccess"

        # ADD YOUR OWN SOFTWARE BELOW THIS LINE
        # Example: "com.mycompany"
    )

    is_known() {
        local file="$1"
        for pattern in "${KNOWN_AGENTS[@]}"; do
            if [[ "$file" == *"$pattern"* ]]; then
                return 0
            fi
        done
        return 1
    }

    # LaunchAgents
    print_check "System LaunchAgents (/Library/LaunchAgents)"
    if [[ -d /Library/LaunchAgents ]]; then
        for f in /Library/LaunchAgents/*.plist; do
            [[ -e "$f" ]] || continue
            fname=$(basename "$f")
            if is_known "$fname"; then
                print_pass "$fname"
            else
                print_warn "Unknown LaunchAgent: $fname — investigate manually"
            fi
        done
    else
        print_pass "No system LaunchAgents directory"
    fi

    # LaunchDaemons
    print_check "System LaunchDaemons (/Library/LaunchDaemons)"
    if [[ -d /Library/LaunchDaemons ]]; then
        for f in /Library/LaunchDaemons/*.plist; do
            [[ -e "$f" ]] || continue
            fname=$(basename "$f")
            if is_known "$fname"; then
                print_pass "$fname"
            else
                print_warn "Unknown LaunchDaemon: $fname — investigate manually"
            fi
        done
    else
        print_pass "No system LaunchDaemons directory"
    fi

    # User LaunchAgents
    print_check "User LaunchAgents (~/Library/LaunchAgents)"
    if [[ -d "$HOME/Library/LaunchAgents" ]]; then
        COUNT=$(ls "$HOME/Library/LaunchAgents/" 2>/dev/null | wc -l | tr -d ' ')
        if [[ "$COUNT" -eq 0 ]]; then
            print_pass "No user LaunchAgents found"
        else
            for f in "$HOME/Library/LaunchAgents/"*.plist; do
                [[ -e "$f" ]] || continue
                fname=$(basename "$f")
                if is_known "$fname"; then
                    print_pass "$fname"
                else
                    print_warn "Unknown user LaunchAgent: $fname"
                fi
            done
        fi
    else
        print_pass "No user LaunchAgents directory"
    fi

    # StartupItems
    print_check "StartupItems (legacy)"
    COUNT=$(ls /Library/StartupItems/ 2>/dev/null | wc -l | tr -d ' ')
    if [[ "$COUNT" -eq 0 ]]; then
        print_pass "StartupItems is empty"
    else
        print_warn "StartupItems contains $COUNT item(s) — legacy persistence method"
        ls /Library/StartupItems/ >> "$REPORT_FILE"
    fi

    # Cron jobs
    print_check "Cron jobs"
    USER_CRON=$(crontab -l 2>/dev/null)
    ROOT_CRON=$(crontab -u root -l 2>/dev/null)
    if [[ -z "$USER_CRON" && -z "$ROOT_CRON" ]]; then
        print_pass "No cron jobs found"
    else
        print_warn "Cron jobs detected — review carefully"
        [[ -n "$USER_CRON" ]] && print_info "User cron: $USER_CRON"
        [[ -n "$ROOT_CRON" ]] && print_info "Root cron: $ROOT_CRON"
    fi

    # PrivilegedHelperTools
    print_check "PrivilegedHelperTools"
    if [[ -d /Library/PrivilegedHelperTools ]]; then
        for f in /Library/PrivilegedHelperTools/*; do
            [[ -e "$f" ]] || continue
            fname=$(basename "$f")
            TEAM=$(codesign -dv "$f" 2>&1 | grep "TeamIdentifier" | awk -F= '{print $2}')
            AUTH=$(codesign -dv "$f" 2>&1 | grep "Authority=" | head -1)
            if [[ -n "$TEAM" ]]; then
                print_pass "$fname — Team: $TEAM"
            else
                # Try with sudo context already available
                TEAM2=$(codesign -dvvv "$f" 2>&1 | grep "TeamIdentifier" | awk -F= '{print $2}')
                if [[ -n "$TEAM2" ]]; then
                    print_pass "$fname — Team: $TEAM2"
                else
                    print_warn "$fname — No Team ID found, verify manually"
                fi
            fi
        done
    else
        print_pass "No PrivilegedHelperTools directory"
    fi
}

# =============================================================================
# PHASE 4 — USER ACCOUNT AUDIT
# =============================================================================
phase4_users() {
    print_header "Phase 4 — User Account Audit"

    # Sudoers
    print_check "Sudoers file integrity"
    NOPASSWD=$(grep -i "NOPASSWD" /etc/sudoers 2>/dev/null | grep -v "^#")
    if [[ -z "$NOPASSWD" ]]; then
        print_pass "No NOPASSWD entries in sudoers"
    else
        print_warn "NOPASSWD found in sudoers — password not required for sudo: $NOPASSWD"
    fi

    # Sudoers drop-ins
    print_check "Sudoers drop-in directory"
    COUNT=$(ls /etc/sudoers.d/ 2>/dev/null | wc -l | tr -d ' ')
    if [[ "$COUNT" -eq 0 ]]; then
        print_pass "sudoers.d is empty"
    else
        print_warn "sudoers.d contains $COUNT file(s) — review carefully"
        ls /etc/sudoers.d/ >> "$REPORT_FILE"
    fi

    # SSH authorized keys
    print_check "SSH authorized_keys"
    if [[ -f "$HOME/.ssh/authorized_keys" ]] && [[ -s "$HOME/.ssh/authorized_keys" ]]; then
        print_warn "authorized_keys exists and is not empty — review SSH keys"
        cat "$HOME/.ssh/authorized_keys" >> "$REPORT_FILE"
    else
        print_pass "No SSH authorized_keys found"
    fi

    if [[ -f /root/.ssh/authorized_keys ]] && [[ -s /root/.ssh/authorized_keys ]]; then
        print_warn "Root authorized_keys exists — potential backdoor"
    else
        print_pass "No root SSH authorized_keys"
    fi
}

# =============================================================================
# PHASE 5 — NETWORK AUDIT
# =============================================================================
phase5_network() {
    print_header "Phase 5 — Network Security"

    # Hosts file
    print_check "Hosts file integrity"
    EXTRA=$(grep -v -E "^(#|127\.0\.0\.1|255\.255\.255\.255|::1|fe80|$)" /etc/hosts 2>/dev/null)
    if [[ -z "$EXTRA" ]]; then
        print_pass "Hosts file is clean — default entries only"
    else
        print_warn "Non-standard entries in /etc/hosts:"
        echo "$EXTRA" >> "$REPORT_FILE"
        print_info "$EXTRA"
    fi

    # DNS servers
    print_check "DNS configuration"
    DNS=$(scutil --dns | grep nameserver | awk '{print $3}' | sort -u)
    print_info "DNS servers: $(echo $DNS | tr '\n' ' ')"
    while IFS= read -r server; do
        # Flag non-RFC1918 non-loopback DNS that isn't a link-local
        if [[ "$server" =~ ^(8\.8\.|1\.1\.|9\.9\.|208\.) ]]; then
            print_info "Public DNS in use: $server"
        elif [[ "$server" =~ ^(192\.168\.|10\.|172\.|fe80|127\.) ]]; then
            print_pass "Local/router DNS: $server"
        else
            print_warn "Unrecognized DNS server: $server — verify this is expected"
        fi
    done <<< "$DNS"

    # Proxy settings
    # Check for actual proxy keys (HTTPProxy, HTTPSProxy, SOCKSProxy etc.)
    # The default empty dictionary with just ExceptionsList and FTPPassive is normal
    print_check "Proxy configuration"
    PROXY=$(scutil --proxy | grep -E "(HTTPProxy|HTTPSProxy|SOCKSProxy|ProxyAutoConfig|HTTPEnable|HTTPSEnable|SOCKSEnable)" | grep -v "Enable = 0")
    if [[ -z "$PROXY" ]]; then
        print_pass "No proxy configured"
    else
        print_warn "Active proxy settings detected — verify these are intentional:"
        print_info "$PROXY"
    fi

    # Listening ports
    print_check "Unexpected listening ports"
    LISTENERS=$(lsof -i -n -P | grep LISTEN | grep -v -E "(launchd|rapportd|ControlCe|ControlCenter|symptomsd|Postman|Brave|Chrome|Firefox|Safari|Docker|zoom|Claude|Cursor|Code)")
    if [[ -z "$LISTENERS" ]]; then
        print_pass "No unexpected listeners found"
    else
        print_warn "Unexpected processes listening on network:"
        echo "$LISTENERS" | while IFS= read -r line; do
            print_info "$line"
        done
    fi
}

# =============================================================================
# PHASE 6 — SOFTWARE AUDIT
# =============================================================================
phase6_software() {
    print_header "Phase 6 — Installed Software"

    # Kernel extensions
    print_check "Third-party kernel extensions"
    KEXTS=$(kextstat 2>/dev/null | grep -v com.apple | grep -v "^Index")
    if [[ -z "$KEXTS" ]]; then
        print_pass "No third-party kernel extensions loaded"
    else
        print_warn "Third-party kexts found — review carefully:"
        echo "$KEXTS" >> "$REPORT_FILE"
        print_info "$KEXTS"
    fi

    # Gatekeeper app assessment
    print_check "Gatekeeper assessment of installed apps"
    REJECTED=$(spctl --assess --verbose /Applications/*.app 2>&1 | grep -E "rejected|UNKNOWN")
    if [[ -z "$REJECTED" ]]; then
        print_pass "All apps in /Applications passed Gatekeeper"
    else
        print_warn "Apps failing Gatekeeper:"
        print_info "$REJECTED"
    fi

    # Homebrew audit
    print_check "Homebrew installation"
    if command -v brew &>/dev/null; then
        print_info "Homebrew is installed"
        print_check "Homebrew security audit"
        BREW_AUDIT=$(brew audit 2>/dev/null | head -20)
        if [[ -z "$BREW_AUDIT" ]]; then
            print_pass "Homebrew audit returned no issues"
        else
            print_warn "Homebrew audit findings:"
            print_info "$BREW_AUDIT"
        fi
    else
        print_info "Homebrew not installed"
    fi
}

# =============================================================================
# PHASE 7 — FILESYSTEM INTEGRITY
# =============================================================================
phase7_filesystem() {
    print_header "Phase 7 — Filesystem Integrity"

    # World-writable files in /usr/local
    print_check "World-writable files in /usr/local"
    WW=$(find /usr/local -perm -o+w -type f 2>/dev/null)
    if [[ -z "$WW" ]]; then
        print_pass "No world-writable files in /usr/local"
    else
        print_warn "World-writable files found:"
        echo "$WW" | while IFS= read -r f; do
            print_info "$f"
        done
    fi

    # Unexpected SUID binaries
    print_check "SUID binaries (non-standard)"
    KNOWN_SUID=(
        "/usr/bin/top" "/usr/bin/atq" "/usr/bin/crontab" "/usr/bin/atrm"
        "/usr/bin/newgrp" "/usr/bin/su" "/usr/bin/batch" "/usr/bin/at"
        "/usr/bin/quota" "/usr/bin/sudo" "/usr/bin/login"
        "/usr/libexec/security_authtrampoline" "/usr/libexec/authopen"
        "/usr/sbin/traceroute6" "/usr/sbin/traceroute" "/bin/ps"
    )
    SUID_FILES=$(find / -perm -4000 -type f 2>/dev/null | grep -v -E "(\/private\/var|snap|ARDAgent)")
    UNEXPECTED_SUID=()
    while IFS= read -r f; do
        FOUND=false
        for known in "${KNOWN_SUID[@]}"; do
            [[ "$f" == "$known" ]] && FOUND=true && break
        done
        $FOUND || UNEXPECTED_SUID+=("$f")
    done <<< "$SUID_FILES"

    if [[ ${#UNEXPECTED_SUID[@]} -eq 0 ]]; then
        print_pass "All SUID binaries are standard macOS binaries"
    else
        for f in "${UNEXPECTED_SUID[@]}"; do
            print_warn "Unexpected SUID binary: $f"
        done
    fi

    # Temp directory check
    print_check "Suspicious files in /tmp"
    SUSPICIOUS_TMP=$(ls -la /tmp/ 2>/dev/null | grep -v -E "(^\.|Brave|Mozilla|vbox|powerlog|zeb_def|BBE72B|Sparkle|^\s*$|total|^d)" | grep -v "^total")
    if [[ -z "$SUSPICIOUS_TMP" ]]; then
        print_pass "/tmp looks clean"
    else
        print_warn "Unexpected files in /tmp:"
        print_info "$SUSPICIOUS_TMP"
    fi

    # Hidden files in home
    print_check "Unexpected hidden files in home directory"
    HIDDEN=$(ls -la "$HOME" | grep "^\." | grep -v -E "(\.$|\.\.|\.(bash|zsh|ssh|config|local|cache|DS_Store|CFUser|Trash|npm|docker|kube|aws|gitconfig|gitignore|vimrc|profile|oh-my-zsh|asdf|pyenv|rbenv|nvm))")
    if [[ -z "$HIDDEN" ]]; then
        print_pass "No unexpected hidden files in home directory"
    else
        print_warn "Unexpected hidden files found in ~/ :"
        print_info "$HIDDEN"
    fi
}

# =============================================================================
# SUMMARY
# =============================================================================
print_summary() {
    echo ""
    echo -e "${BOLD}${BLUE}============================================================${RESET}"
    echo -e "${BOLD}${BLUE}  AUDIT SUMMARY${RESET}"
    echo -e "${BOLD}${BLUE}============================================================${RESET}"
    echo ""

    if [[ "$ISSUES_FOUND" -eq 0 ]]; then
        echo -e "  ${GREEN}${BOLD}✅ All checks passed — excellent security posture!${RESET}"
    elif [[ "$ISSUES_FOUND" -le 3 ]]; then
        echo -e "  ${YELLOW}${BOLD}⚠️  $ISSUES_FOUND issue(s) found — review warnings above${RESET}"
    else
        echo -e "  ${RED}${BOLD}❌ $ISSUES_FOUND issue(s) found — action required${RESET}"
    fi

    if [[ "$FIXES_APPLIED" -gt 0 ]]; then
        echo -e "  ${GREEN}${BOLD}🔧 $FIXES_APPLIED fix(es) applied during this run${RESET}"
    fi

    echo ""
    echo -e "  ${BOLD}Report saved to:${RESET} $REPORT_FILE"
    echo ""

    # Write summary to report
    cat >> "$REPORT_FILE" <<EOF

---

## Summary

| Metric | Value |
|--------|-------|
| Total Issues Found | $ISSUES_FOUND |
| Fixes Applied | $FIXES_APPLIED |
| Audit Date | $(date) |
| macOS Version | $(sw_vers -productVersion) |
| Hostname | $(hostname) |

$(if [[ "$ISSUES_FOUND" -eq 0 ]]; then echo "**Result: ✅ All checks passed — excellent security posture!**"; elif [[ "$ISSUES_FOUND" -le 3 ]]; then echo "**Result: ⚠️ $ISSUES_FOUND issue(s) found — review warnings**"; else echo "**Result: ❌ $ISSUES_FOUND issue(s) found — action required**"; fi)
EOF
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    require_root
    init_report
    phase1_baseline
    phase2_security_features
    phase3_persistence
    phase4_users
    phase5_network
    phase6_software
    phase7_filesystem
    print_summary
}

main "$@"
