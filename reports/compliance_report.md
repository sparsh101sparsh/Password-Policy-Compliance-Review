# Password-Policy Compliance Review Report

- **Host:** `sparsh’s MacBook Air` (macOS 27.2.1 (26B131))
- **Audited User:** `iamsparsh00321`
- **Organization Baseline:** Acme Enterprise Security Baseline (v2.4)
- **Generated At:** 2026-11-27T20:28:53+05:30
- **Overall Compliance Score:** **50.0%** (6/12 compliant, 5 non-compliant, 1 review)

## Comparison Matrix

| ID | Control | Stated Requirement | Observed System Setting | Status | Severity |
|---|---|---|---|---|---|
| REQ-01 | Minimum Password Length | >= 12 characters | 4 characters (policy: com.apple.defaultpasswordpolicy.fde) | **NON-COMPLIANT** | CRITICAL |
| REQ-02 | Character Diversity / Complexity Rule | Must enforce >= 3 of 4 classes (upper, lower, digit, symbol) or >= 15-char passphrase | No complexity rules (only `policyAttributePassword matches '.{4,}+'`) | **NON-COMPLIANT** | HIGH |
| REQ-03 | Password History Enforcement | Remember at least 5 previous passwords | Not configured (0) | **NON-COMPLIANT** | MEDIUM |
| REQ-04 | Failed Login Attempt Lockout | Lock account after <= 5 failed attempts | Not configured (unlimited) | **NON-COMPLIANT** | HIGH |
| REQ-05 | Maximum Password Age / Expiration Policy | Defined expiration policy (<= 365 days or risk-based breach check) | No expiration configured | **REVIEW** | LOW |
| REQ-06 | Domain / MDM Password Policy Management | Managed via Active Directory or MDM profile | Standalone local host (AD: No, DEP: No, MDM: No) | **NON-COMPLIANT** | MEDIUM |
| REQ-07 | Automatic Login Disabled | Disabled (autoLoginUser unset) | Disabled (autoLoginUser key absent) | **COMPLIANT** | HIGH |
| REQ-08 | Guest Account Disabled | Disabled (GuestEnabled = 0) | Disabled (GuestEnabled = 0) | **COMPLIANT** | MEDIUM |
| REQ-09 | Screen Lock Timeout | <= 300 seconds (5 minutes) | 300 seconds (5 min) | **COMPLIANT** | MEDIUM |
| REQ-10 | Password Hashing Algorithm | PBKDF2-HMAC-SHA512 / Salted ShadowHash | SALTED-SHA512-PBKDF2 + SRP-RFC5054-4096 + SecureToken | **COMPLIANT** | HIGH |
| REQ-11 | Full Disk Encryption (FileVault) | Enabled (FileVault On) | FileVault is On | **COMPLIANT** | HIGH |
| REQ-12 | Directory-Backed PAM Authentication | pam_opendirectory.so enforced on passwd, sudo, authorization | pam_opendirectory.so active in passwd, sudo, authorization | **COMPLIANT** | MEDIUM |

## Recommended Changes

- **[CRITICAL] REQ-01 — Minimum Password Length**: Increase minimum password length from 4 to 12+ characters via `pwpolicy -setaccountpolicies` or an MDM Passcode payload.
- **[HIGH] REQ-02 — Character Diversity / Complexity Rule**: Add character-class rules (uppercase, lowercase, digit, special character) or enforce >= 15-character passphrases in `policyCategoryPasswordContent`.
- **[MEDIUM] REQ-03 — Password History Enforcement**: Set `policyAttributePasswordHistoryDepth` to 5 in `policyCategoryPasswordChange`.
- **[HIGH] REQ-04 — Failed Login Attempt Lockout**: Configure `policyAttributeMaximumFailedAuthentications` = 5 with an auto-unlock window (`policyAttributeMinutesUntilFailedAuthenticationReset`).
- **[LOW] REQ-05 — Maximum Password Age / Expiration Policy**: Define `policyAttributeExpiresEveryNDays` <= 365 days (or document an explicit NIST 800-63B exception paired with compromised-password screening).
- **[MEDIUM] REQ-06 — Domain / MDM Password Policy Management**: Enroll workstation into enterprise MDM (e.g., Jamf/Kandji/Intune) and push a `com.apple.mobiledevice.passwordpolicy` configuration profile.
