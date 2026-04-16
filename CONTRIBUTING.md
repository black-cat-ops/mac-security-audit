# Contributing to macOS Security Audit

Thank you for your interest in contributing! This project aims to be a practical, community-maintained security audit tool for macOS. Here's how you can help.

---

## Ways to Contribute

- 🐛 **Bug reports** — found a false positive or broken check?
- ✨ **New audit checks** — know a security surface we're missing?
- 🔧 **Fix improvements** — better remediation for a known issue?
- 📄 **Documentation** — clearer explanations, better examples
- 🧪 **Testing** — verified on a new macOS version or hardware?

---

## Getting Started

```bash
# Fork and clone
git clone https://github.com/black-cat-ops/mac-security-audit.git
cd mac-security-audit

# Create a feature branch
git checkout -b feature/your-feature-name

# Make your changes, then test
sudo bash mac_security_audit.sh

# Commit with a clear message
git commit -m "feat: add check for XPC service permissions"

# Push and open a Pull Request
git push origin feature/your-feature-name
```

---

## Adding a New Audit Check

Each check follows this pattern inside the appropriate phase function:

```bash
print_check "Description of what you're checking"

RESULT=$(your_command_here 2>/dev/null)

if [[ condition_for_pass ]]; then
    print_pass "Clear pass message"
else
    print_warn "Clear warning message with actionable detail"
    # Optional: offer a fix
    if ask_fix "Description of the fix to apply"; then
        your_fix_command
        print_pass "Fix applied successfully"
        ((FIXES_APPLIED++))
    fi
fi
```

### Guidelines for New Checks

- **One check, one concern** — keep each check focused
- **Explain the risk** — warn messages should say *why* something matters
- **Never auto-fix without asking** — always use `ask_fix()` for remediation
- **Handle errors gracefully** — use `2>/dev/null` and check for empty results
- **Test on clean and dirty systems** — verify both pass and fail paths work

---

## Coding Standards

- Pure bash — no external dependencies beyond standard macOS tools
- Use the provided helper functions (`print_pass`, `print_warn`, `print_fail`, `print_info`, `print_check`)
- Quote all variables: `"$VAR"` not `$VAR`
- Use `[[ ]]` for conditionals, not `[ ]`
- Add comments for non-obvious commands
- Keep line length under 100 characters where possible

---

## Reporting Bugs

Please open a GitHub Issue with:

- macOS version (`sw_vers`)
- Hardware (Apple Silicon / Intel)
- The check that failed or produced incorrect output
- Expected vs actual behavior
- Relevant terminal output (redact any sensitive info)

---

## False Positives

If a legitimate tool is being flagged as suspicious, open an issue with:

- The tool name and version
- The check that flagged it
- Evidence of legitimacy (vendor URL, code signature info)

We maintain allowlists for known-good tools and will update them promptly for legitimate software.

---

## Testing Checklist

Before submitting a PR, please verify:

- [ ] Script runs without errors on your macOS version
- [ ] New checks produce correct PASS output on a clean system
- [ ] New checks produce correct WARN/FAIL on a system with the issue present
- [ ] Markdown report is generated correctly
- [ ] No new external dependencies introduced
- [ ] Helper functions used consistently

---

## Commit Message Format

Use conventional commits:

```
feat: add check for XPC service permissions
fix: correct SUID binary allowlist for macOS 15
docs: update README with Sequoia compatibility note
chore: add macOS 26 to tested versions
```

---

## Code of Conduct

- Be respectful and constructive
- Security research should be responsible — don't include exploit code
- Keep the focus on defensive security tooling

---

Thank you for helping make macOS more secure! 🔒
