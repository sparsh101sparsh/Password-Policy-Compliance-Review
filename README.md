# Password-Policy Compliance Review

An automated macOS Password-Policy Compliance Review toolkit that inspects local and domain password settings using native system administration utilities, compares them against stated organizational requirements (`organization_policy.json`), highlights security gaps, generates a compliant `pwpolicy` deployment profile, and builds an interactive HTML dashboard.

## System Administration Tools Used

- `pwpolicy -getglobalpolicy` & `pwpolicy -getaccountpolicies` — Local password length, complexity, history, lockout, and expiration XML plist rules
- `sysadminctl -screenLock status` — Screen lock idle timeout enforcement
- `dsconfigad -show` & `profiles status -type enrollment` — Active Directory binding, DEP, and MDM policy management status
- `dscl . -read /Users/<user> AuthenticationAuthority` — Local credential hashing scheme (`SALTED-SHA512-PBKDF2`)
- `defaults read /Library/Preferences/com.apple.loginwindow` — Automatic login and Guest account settings
- `fdesetup status` — FileVault full-disk encryption verification
- `/etc/pam.d/{passwd,sudo,authorization}` — PAM directory authentication enforcement

## Usage

```bash
# Run full compliance audit + generate JSON, Markdown, Plist, and HTML Dashboard
python3 audit_password_policy.py

# Test candidate passwords against Current Local Policy vs Organization Policy
python3 audit_password_policy.py --test-only --test-passwords "1234" "admin123" "Tr0ub4dor&3!"

# Simulate & verify compliance using the generated policy profile (read-only; does not alter system settings)
python3 audit_password_policy.py --simulate-plist reports/recommended_account_policy.plist

# Run unit tests
python3 -m unittest discover -s tests -v
```

## Outputs

- `reports/compliance_report.json` — Machine-readable audit telemetry and comparison results
- `reports/compliance_report.md` — Markdown summary report and remediation checklist
- `reports/recommended_account_policy.plist` — Ready-to-deploy Apple `pwpolicy` XML configuration
- `reports/dashboard.html` — Interactive multi-tab compliance dashboard
- `Password_Policy_Compliance_Review_Report.pdf` — Screenshot-driven project working report
