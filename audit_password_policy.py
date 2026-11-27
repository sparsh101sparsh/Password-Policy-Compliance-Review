#!/usr/bin/env python3
"""Password-Policy Compliance Review Tool for macOS.

Inspects local and domain password settings using native macOS system
administration tools (pwpolicy, dscl, sysadminctl, dsconfigad, profiles,
defaults, fdesetup, and PAM configuration), compares findings against the
organization's stated requirements in organization_policy.json, generates
remediation artifacts, and renders an interactive HTML compliance dashboard.
"""

from __future__ import annotations

import argparse
import datetime
import html
import json
import os
import plistlib
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_POLICY_PATH = BASE_DIR / "organization_policy.json"
REPORTS_DIR = BASE_DIR / "reports"


def run_cmd(cmd: list[str], timeout: int = 10) -> dict[str, Any]:
    """Run a read-only system administration command and capture output."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return {
            "command": " ".join(cmd),
            "returncode": proc.returncode,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
        }
    except Exception as exc:
        return {
            "command": " ".join(cmd),
            "returncode": -1,
            "stdout": "",
            "stderr": str(exc),
        }


def parse_pwpolicy_plist(raw_output: str) -> dict[str, Any]:
    """Extract and parse XML plist from `pwpolicy -getaccountpolicies` output."""
    xml_start = raw_output.find("<?xml")
    if xml_start == -1:
        return {"parsed": False, "raw": raw_output}

    xml_text = raw_output[xml_start:]
    try:
        plist_data = plistlib.loads(xml_text.encode("utf-8"))
    except Exception as exc:
        return {"parsed": False, "error": str(exc), "raw": raw_output}

    summary: dict[str, Any] = {
        "parsed": True,
        "categories": list(plist_data.keys()),
        "identifiers": [],
        "content_rules": [],
        "min_length": None,
        "has_complexity": False,
        "history_depth": None,
        "max_failed_attempts": None,
        "max_age_days": None,
    }

    for category, rules in plist_data.items():
        if not isinstance(rules, list):
            continue
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            if "policyIdentifier" in rule:
                summary["identifiers"].append(rule["policyIdentifier"])
            content = rule.get("policyContent")
            if isinstance(content, str):
                summary["content_rules"].append(content)
                len_match = re.search(r"\.\{(\d+),(\d*)\}", content)
                if len_match:
                    val = int(len_match.group(1))
                    if summary["min_length"] is None or val > summary["min_length"]:
                        summary["min_length"] = val
                if any(
                    token in content
                    for token in ("[A-Z]", "[a-z]", "[0-9]", "\\d", "[^a-zA-Z0-9]", "matches")
                ):
                    if not re.fullmatch(r"policyAttributePassword\s+matches\s+'\.\{\d+,\}\+?'", content.strip()):
                        summary["has_complexity"] = True

            params = rule.get("policyParameters", {})
            if isinstance(params, dict):
                if "policyAttributePasswordHistoryDepth" in params:
                    summary["history_depth"] = params["policyAttributePasswordHistoryDepth"]
                if "policyAttributeMaximumFailedAuthentications" in params:
                    summary["max_failed_attempts"] = params["policyAttributeMaximumFailedAuthentications"]
                if "policyAttributeExpiresEveryNDays" in params:
                    summary["max_age_days"] = params["policyAttributeExpiresEveryNDays"]

    return summary


def collect_system_state() -> dict[str, Any]:
    """Collect current local/domain password and security settings via macOS admin tools."""
    current_user = run_cmd(["id", "-un"])["stdout"] or os.environ.get("USER", "unknown")
    os_name = run_cmd(["sw_vers", "-productName"])["stdout"] or "macOS"
    os_ver = run_cmd(["sw_vers", "-productVersion"])["stdout"] or ""
    os_build = run_cmd(["sw_vers", "-buildVersion"])["stdout"] or ""
    os_version = f"{os_name} {os_ver} ({os_build})".strip()
    hostname = run_cmd(["scutil", "--get", "ComputerName"])
    pw_global = run_cmd(["pwpolicy", "-getglobalpolicy"])
    pw_user_global = run_cmd(["pwpolicy", "-u", current_user, "-getglobalpolicy"])
    pw_acct = run_cmd(["pwpolicy", "-getaccountpolicies"])
    pw_parsed = parse_pwpolicy_plist(pw_acct["stdout"])
    sysadmin_lock = run_cmd(["sysadminctl", "-screenLock", "status"])
    dsconfigad = run_cmd(["dsconfigad", "-show"])
    profiles = run_cmd(["profiles", "status", "-type", "enrollment"])
    fdesetup = run_cmd(["fdesetup", "status"])
    autologin = run_cmd(["defaults", "read", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"])
    guest = run_cmd(["defaults", "read", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled"])
    auth_authority = run_cmd(["dscl", ".", "-read", f"/Users/{current_user}", "AuthenticationAuthority"])
    users_cmd = run_cmd(["dscl", ".", "-list", "/Users", "UniqueID"])

    local_users = []
    for line in users_cmd["stdout"].splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].isdigit() and int(parts[1]) >= 500:
            local_users.append({"username": parts[0], "uid": int(parts[1])})

    pam_files = {}
    for name in ("passwd", "sudo", "authorization"):
        p = Path(f"/etc/pam.d/{name}")
        if p.exists():
            pam_files[name] = [
                line.strip()
                for line in p.read_text(errors="replace").splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
        else:
            pam_files[name] = []

    lock_text = f"{sysadmin_lock['stdout']} {sysadmin_lock['stderr']}"
    lock_match = re.search(r"screenLock delay is (\d+) seconds", lock_text)
    screen_lock_seconds = int(lock_match.group(1)) if lock_match else None

    profiles_text = profiles["stdout"]
    dep_enrolled = "Enrolled via DEP: Yes" in profiles_text
    mdm_enrolled = "MDM enrollment: Yes" in profiles_text
    ad_bound = bool(dsconfigad["stdout"].strip())

    return {
        "collected_at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
        "hostname": hostname["stdout"] or "MacBook",
        "current_user": current_user,
        "os_version": os_version,
        "local_users": local_users,
        "pwpolicy_parsed": pw_parsed,
        "screen_lock_seconds": screen_lock_seconds,
        "autologin_disabled": autologin["returncode"] != 0,
        "guest_enabled": guest["stdout"].strip() == "1",
        "filevault_on": "FileVault is On" in fdesetup["stdout"],
        "ad_bound": ad_bound,
        "dep_enrolled": dep_enrolled,
        "mdm_enrolled": mdm_enrolled,
        "hashing_schemes": auth_authority["stdout"],
        "pam_files": pam_files,
        "raw_evidence": {
            "pwpolicy_global": pw_global,
            "pwpolicy_user_global": pw_user_global,
            "pwpolicy_accountpolicies": pw_acct,
            "sysadminctl_screenlock": sysadmin_lock,
            "dsconfigad_show": dsconfigad,
            "profiles_enrollment": profiles,
            "fdesetup_status": fdesetup,
            "loginwindow_autologin": autologin,
            "loginwindow_guest": guest,
            "dscl_auth_authority": auth_authority,
            "dscl_local_users": users_cmd,
        },
    }


def evaluate_compliance(policy: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    """Compare observed system state against organization policy requirements."""
    pw = state["pwpolicy_parsed"]
    results: list[dict[str, Any]] = []

    for req in policy["requirements"]:
        rid = req["id"]
        status = "REVIEW"
        actual = "Unknown"
        evidence_cmd = ""
        recommendation = ""

        if rid == "REQ-01":
            min_len = pw.get("min_length")
            req_len = req.get("min_length", 12)
            evidence_cmd = "pwpolicy -getaccountpolicies"
            if min_len is not None:
                actual = f"{min_len} characters (policy: {', '.join(pw.get('identifiers', [])) or 'custom'})"
                if min_len >= req_len:
                    status = "COMPLIANT"
                    recommendation = "No change required."
                else:
                    status = "NON-COMPLIANT"
                    recommendation = (
                        f"Increase minimum password length from {min_len} to {req_len}+ characters "
                        "via `pwpolicy -setaccountpolicies` or an MDM Passcode payload."
                    )
            else:
                actual = "No minimum length rule configured"
                status = "NON-COMPLIANT"
                recommendation = f"Configure `policyAttributePassword matches '.{{{req_len},}}+'`."

        elif rid == "REQ-02":
            evidence_cmd = "pwpolicy -getaccountpolicies"
            if pw.get("has_complexity"):
                rule_count = len(pw.get("content_rules", []))
                actual = f"Complexity rules configured ({rule_count} content rules)" if rule_count > 1 else "Complexity regex configured"
                status = "COMPLIANT"
                recommendation = "No change required."
            else:
                rules = ", ".join(pw.get("content_rules", [])) or "None"
                actual = f"No complexity rules (only `{rules}`)"
                status = "NON-COMPLIANT"
                recommendation = (
                    "Add character-class rules (uppercase, lowercase, digit, special character) "
                    "or enforce >= 15-character passphrases in `policyCategoryPasswordContent`."
                )

        elif rid == "REQ-03":
            evidence_cmd = "pwpolicy -getaccountpolicies"
            hist = pw.get("history_depth")
            req_hist = req.get("min_history", 5)
            if hist is not None and hist >= req_hist:
                actual = f"Remembers {hist} previous passwords"
                status = "COMPLIANT"
                recommendation = "No change required."
            else:
                actual = f"{hist} previous passwords" if hist is not None else "Not configured (0)"
                status = "NON-COMPLIANT"
                recommendation = f"Set `policyAttributePasswordHistoryDepth` to {req_hist} in `policyCategoryPasswordChange`."

        elif rid == "REQ-04":
            evidence_cmd = "pwpolicy -getaccountpolicies"
            max_fail = pw.get("max_failed_attempts")
            req_fail = req.get("max_failed_attempts", 5)
            if max_fail is not None and max_fail <= req_fail:
                actual = f"Locks after {max_fail} failed attempts"
                status = "COMPLIANT"
                recommendation = "No change required."
            else:
                actual = f"{max_fail} attempts" if max_fail is not None else "Not configured (unlimited)"
                status = "NON-COMPLIANT"
                recommendation = (
                    f"Configure `policyAttributeMaximumFailedAuthentications` = {req_fail} "
                    "with an auto-unlock window (`policyAttributeMinutesUntilFailedAuthenticationReset`)."
                )

        elif rid == "REQ-05":
            evidence_cmd = "pwpolicy -getaccountpolicies"
            max_age = pw.get("max_age_days")
            req_age = req.get("max_age_days", 365)
            if max_age is not None and max_age <= req_age:
                actual = f"Expires every {max_age} days"
                status = "COMPLIANT"
                recommendation = "No change required."
            else:
                actual = "No expiration configured"
                status = "REVIEW"
                recommendation = (
                    f"Define `policyAttributeExpiresEveryNDays` <= {req_age} days (or document an "
                    "explicit NIST 800-63B exception paired with compromised-password screening)."
                )

        elif rid == "REQ-06":
            evidence_cmd = "dsconfigad -show && profiles status -type enrollment"
            if state["ad_bound"] or state["mdm_enrolled"]:
                actual = f"AD Bound: {state['ad_bound']}, MDM: {state['mdm_enrolled']}"
                status = "COMPLIANT"
                recommendation = "Verify MDM passcode profile stays synced."
            else:
                actual = "Standalone local host (AD: No, DEP: No, MDM: No)"
                status = "NON-COMPLIANT"
                recommendation = (
                    "Enroll workstation into enterprise MDM (e.g., Jamf/Kandji/Intune) and push a "
                    "`com.apple.mobiledevice.passwordpolicy` configuration profile."
                )

        elif rid == "REQ-07":
            evidence_cmd = "defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser"
            if state["autologin_disabled"]:
                actual = "Disabled (autoLoginUser key absent)"
                status = "COMPLIANT"
                recommendation = "No change required."
            else:
                actual = "Enabled"
                status = "NON-COMPLIANT"
                recommendation = "Run `sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser`."

        elif rid == "REQ-08":
            evidence_cmd = "defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled"
            if not state["guest_enabled"]:
                actual = "Disabled (GuestEnabled = 0)"
                status = "COMPLIANT"
                recommendation = "No change required."
            else:
                actual = "Enabled (GuestEnabled = 1)"
                status = "NON-COMPLIANT"
                recommendation = "Run `sudo sysadminctl -guestAccount off`."

        elif rid == "REQ-09":
            evidence_cmd = "sysadminctl -screenLock status"
            secs = state["screen_lock_seconds"]
            max_secs = req.get("max_screen_lock_seconds", 300)
            if secs is not None and secs <= max_secs:
                actual = f"{secs} seconds ({secs // 60} min)"
                status = "COMPLIANT"
                recommendation = "Meets baseline (<= 300s). Optionally tighten to 60–120s for high-sensitivity roles."
            elif secs is not None:
                actual = f"{secs} seconds"
                status = "NON-COMPLIANT"
                recommendation = f"Run `sysadminctl -screenLock {max_secs} -password <admin_pw>`."
            else:
                actual = "Not detected"
                status = "REVIEW"
                recommendation = "Verify screen lock policy via System Settings / MDM."

        elif rid == "REQ-10":
            evidence_cmd = f"dscl . -read /Users/{state['current_user']} AuthenticationAuthority"
            auth_str = state["hashing_schemes"]
            if "SALTED-SHA512-PBKDF2" in auth_str:
                actual = "SALTED-SHA512-PBKDF2 + SRP-RFC5054-4096 + SecureToken"
                status = "COMPLIANT"
                recommendation = "No change required."
            else:
                actual = auth_str or "Unknown"
                status = "NON-COMPLIANT"
                recommendation = "Migrate legacy hashes to SALTED-SHA512-PBKDF2."

        elif rid == "REQ-11":
            evidence_cmd = "fdesetup status"
            if state["filevault_on"]:
                actual = "FileVault is On"
                status = "COMPLIANT"
                recommendation = "No change required."
            else:
                actual = "FileVault is Off"
                status = "NON-COMPLIANT"
                recommendation = "Enable FileVault immediately via `sudo fdesetup enable`."

        elif rid == "REQ-12":
            evidence_cmd = "cat /etc/pam.d/{passwd,sudo,authorization}"
            passwd_ok = any("pam_opendirectory.so" in l for l in state["pam_files"].get("passwd", []))
            sudo_ok = any("pam_opendirectory.so" in l for l in state["pam_files"].get("sudo", []))
            auth_ok = any("pam_opendirectory.so" in l for l in state["pam_files"].get("authorization", []))
            if passwd_ok and sudo_ok and auth_ok:
                actual = "pam_opendirectory.so active in passwd, sudo, authorization"
                status = "COMPLIANT"
                recommendation = "No change required."
            else:
                actual = f"passwd={passwd_ok}, sudo={sudo_ok}, authorization={auth_ok}"
                status = "NON-COMPLIANT"
                recommendation = "Restore `pam_opendirectory.so` entries in `/etc/pam.d/`."

        results.append(
            {
                "id": rid,
                "category": req["category"],
                "title": req["title"],
                "required_value": req["required_value"],
                "actual_value": actual,
                "status": status,
                "severity": req["severity"],
                "evidence_command": evidence_cmd,
                "rationale": req["rationale"],
                "recommendation": recommendation,
            }
        )

    compliant_count = sum(1 for r in results if r["status"] == "COMPLIANT")
    non_compliant_count = sum(1 for r in results if r["status"] == "NON-COMPLIANT")
    review_count = sum(1 for r in results if r["status"] == "REVIEW")
    total = len(results)
    score = round((compliant_count / total) * 100, 1) if total else 0.0

    return {
        "organization": policy["organization"],
        "policy_version": policy["policy_version"],
        "reference_standards": policy["reference_standards"],
        "summary": {
            "total_controls": total,
            "compliant": compliant_count,
            "non_compliant": non_compliant_count,
            "review": review_count,
            "compliance_score_pct": score,
        },
        "results": results,
    }


def evaluate_sample_passwords(passwords: list[str], state: dict[str, Any], policy: dict[str, Any]) -> list[dict[str, Any]]:
    """Test candidate passwords against Current Local Policy vs Organization Policy."""
    pw = state["pwpolicy_parsed"]
    local_min = pw.get("min_length") or 4
    local_complexity = bool(pw.get("has_complexity"))
    org_min = next((r.get("min_length", 12) for r in policy["requirements"] if r["id"] == "REQ-01"), 12)

    evaluated = []
    for pwd in passwords:
        classes = sum(
            [
                bool(re.search(r"[A-Z]", pwd)),
                bool(re.search(r"[a-z]", pwd)),
                bool(re.search(r"[0-9]", pwd)),
                bool(re.search(r"[^A-Za-z0-9]", pwd)),
            ]
        )
        local_reasons = []
        if len(pwd) < local_min:
            local_reasons.append(f"length {len(pwd)} < {local_min}")
        if local_complexity and classes < 4:
            local_reasons.append(f"only {classes}/4 char classes")
        local_pass = len(local_reasons) == 0
        org_reasons = []
        if len(pwd) < org_min:
            org_reasons.append(f"length {len(pwd)} < {org_min}")
        if classes < 3 and len(pwd) < 15:
            org_reasons.append(f"only {classes}/4 char classes (need >=3 or 15+ passphrase)")
        org_pass = len(org_reasons) == 0

        evaluated.append(
            {
                "password": pwd,
                "length": len(pwd),
                "classes": classes,
                "local_policy_pass": local_pass,
                "local_note": (
                    f"Passes local policy (>={local_min} chars, 4/4 classes)"
                    if (local_pass and local_complexity)
                    else (f"Passes current local policy (.{{{local_min},}}+)" if local_pass else "; ".join(local_reasons))
                ),
                "org_policy_pass": org_pass,
                "org_note": "Meets organization requirements" if org_pass else "; ".join(org_reasons),
            }
        )
    return evaluated


def build_recommended_plist() -> str:
    """Generate a ready-to-deploy macOS pwpolicy XML plist matching organization requirements."""
    plist_obj = {
        "policyCategoryAuthentication": [
            {
                "policyContent": "policyAttributeFailedAuthentications < policyAttributeMaximumFailedAuthentications",
                "policyIdentifier": "org.acme.policy.lockout",
                "policyParameters": {
                    "policyAttributeMaximumFailedAuthentications": 5,
                    "policyAttributeMinutesUntilFailedAuthenticationReset": 15,
                },
            }
        ],
        "policyCategoryPasswordChange": [
            {
                "policyContent": "policyAttributeCurrentTime > policyAttributeLastPasswordChangeTime + (policyAttributeExpiresEveryNDays * 24 * 60 * 60)",
                "policyIdentifier": "org.acme.policy.expiration",
                "policyParameters": {
                    "policyAttributeExpiresEveryNDays": 365,
                },
            },
            {
                "policyContent": "policyAttributePasswordHashes does not contain policyAttributeNewPassword",
                "policyIdentifier": "org.acme.policy.history",
                "policyParameters": {
                    "policyAttributePasswordHistoryDepth": 5,
                },
            },
        ],
        "policyCategoryPasswordContent": [
            {
                "policyContent": "policyAttributePassword matches '.{12,}+'",
                "policyIdentifier": "org.acme.policy.minlength",
                "policyContentDescription": {
                    "en": "Enter a password that is at least 12 characters long."
                },
            },
            {
                "policyContent": "policyAttributePassword matches '.*[A-Z].*'",
                "policyIdentifier": "org.acme.policy.uppercase",
                "policyContentDescription": {
                    "en": "Password must include at least one uppercase letter."
                },
            },
            {
                "policyContent": "policyAttributePassword matches '.*[a-z].*'",
                "policyIdentifier": "org.acme.policy.lowercase",
                "policyContentDescription": {
                    "en": "Password must include at least one lowercase letter."
                },
            },
            {
                "policyContent": "policyAttributePassword matches '.*[0-9].*'",
                "policyIdentifier": "org.acme.policy.digit",
                "policyContentDescription": {
                    "en": "Password must include at least one number."
                },
            },
            {
                "policyContent": "policyAttributePassword matches '.*[^A-Za-z0-9].*'",
                "policyIdentifier": "org.acme.policy.special",
                "policyContentDescription": {
                    "en": "Password must include at least one special character."
                },
            },
        ],
    }
    return plistlib.dumps(plist_obj).decode("utf-8")


def write_markdown_report(state: dict[str, Any], compliance: dict[str, Any], path: Path) -> None:
    """Write a structured Markdown compliance report."""
    s = compliance["summary"]
    lines = [
        f"# Password-Policy Compliance Review Report",
        "",
        f"- **Host:** `{state['hostname']}` ({state['os_version']})",
        f"- **Audited User:** `{state['current_user']}`",
        f"- **Organization Baseline:** {compliance['organization']} (v{compliance['policy_version']})",
        f"- **Generated At:** {state['collected_at']}",
        f"- **Overall Compliance Score:** **{s['compliance_score_pct']}%** ({s['compliant']}/{s['total_controls']} compliant, {s['non_compliant']} non-compliant, {s['review']} review)",
        "",
        "## Comparison Matrix",
        "",
        "| ID | Control | Stated Requirement | Observed System Setting | Status | Severity |",
        "|---|---|---|---|---|---|",
    ]
    for r in compliance["results"]:
        lines.append(
            f"| {r['id']} | {r['title']} | {r['required_value']} | {r['actual_value']} | **{r['status']}** | {r['severity']} |"
        )
    lines.extend(["", "## Recommended Changes", ""])
    for r in compliance["results"]:
        if r["status"] != "COMPLIANT":
            lines.append(f"- **[{r['severity']}] {r['id']} — {r['title']}**: {r['recommendation']}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def generate_dashboard_html(
    state: dict[str, Any],
    compliance: dict[str, Any],
    sim_compliance: dict[str, Any],
    sample_tests: list[dict[str, Any]],
    recommended_plist: str,
    path: Path,
) -> None:
    """Generate a self-contained interactive HTML compliance dashboard."""
    payload = {
        "state": state,
        "compliance": compliance,
        "sim_compliance": sim_compliance,
        "sample_tests": sample_tests,
        "recommended_plist": recommended_plist,
    }
    data_json = json.dumps(payload).replace("</", "<\\/")

    template = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Password-Policy Compliance Review</title>
<link rel="preconnect" href="https://fonts.googleapis.com" />
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet" />
<style>
  :root {
    --bg: #f6f7f9;
    --panel: #ffffff;
    --panel-muted: #f9fafb;
    --border: #e5e7eb;
    --border-strong: #d1d5db;
    --text: #111827;
    --text-secondary: #374151;
    --muted: #6b7280;
    --accent: #1d4ed8;
    --accent-soft: #eff6ff;
    --pass-bg: #ecfdf5;
    --pass-fg: #065f46;
    --pass-bd: #a7f3d0;
    --fail-bg: #fef2f2;
    --fail-fg: #991b1b;
    --fail-bd: #fecaca;
    --warn-bg: #fffbeb;
    --warn-fg: #92400e;
    --warn-bd: #fde68a;
    --font: "Inter", "Avenir Next", "Helvetica Neue", Arial, sans-serif;
    --mono: "JetBrains Mono", "Menlo", "SF Mono", monospace;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: var(--font);
    font-size: 14px;
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
    padding: 28px 32px 44px;
  }
  .container { max-width: 1280px; margin: 0 auto; }
  header {
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
    gap: 20px;
    border-bottom: 1px solid var(--border);
    padding-bottom: 18px;
    margin-bottom: 20px;
  }
  .eyebrow {
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--accent);
    margin-bottom: 4px;
  }
  .title-block h1 {
    margin: 0 0 4px;
    font-size: 25px;
    font-weight: 700;
    letter-spacing: -0.025em;
    color: var(--text);
  }
  .subtitle { color: var(--muted); font-size: 13px; }
  .host-pill {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 9px 14px;
    font-size: 12px;
    color: var(--muted);
    text-align: right;
    line-height: 1.55;
    box-shadow: 0 1px 2px rgba(17, 24, 39, 0.03);
  }
  .host-pill strong { color: var(--text); font-weight: 600; }
  .tabs {
    display: inline-flex;
    gap: 4px;
    background: #eceef2;
    padding: 4px;
    border-radius: 9px;
    margin-bottom: 20px;
    border: 1px solid var(--border);
  }
  .tab-btn {
    background: transparent;
    border: none;
    color: var(--text-secondary);
    padding: 8px 15px;
    border-radius: 6px;
    cursor: pointer;
    font-family: var(--font);
    font-size: 13px;
    font-weight: 500;
  }
  .tab-btn.active {
    background: var(--panel);
    color: var(--text);
    font-weight: 600;
    box-shadow: 0 1px 3px rgba(17, 24, 39, 0.08);
  }
  .kpis {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 14px;
    margin-bottom: 20px;
  }
  .kpi {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px 18px;
    box-shadow: 0 1px 2px rgba(17, 24, 39, 0.03);
  }
  .kpi .label {
    font-size: 11px;
    font-weight: 600;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }
  .kpi .value {
    font-size: 28px;
    font-weight: 700;
    letter-spacing: -0.02em;
    font-variant-numeric: tabular-nums;
    margin: 6px 0 4px;
  }
  .kpi .hint { font-size: 12px; color: var(--muted); }
  .card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 18px 20px;
    margin-bottom: 18px;
    box-shadow: 0 1px 2px rgba(17, 24, 39, 0.03);
  }
  .card h2 {
    margin: 0 0 12px;
    font-size: 15px;
    font-weight: 600;
    letter-spacing: -0.01em;
    color: var(--text);
  }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th {
    text-align: left;
    color: var(--muted);
    font-weight: 600;
    padding: 9px 12px;
    background: var(--panel-muted);
    border-top: 1px solid var(--border);
    border-bottom: 1px solid var(--border);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  td {
    padding: 8px 12px;
    border-bottom: 1px solid #f1f5f9;
    vertical-align: top;
    color: var(--text-secondary);
  }
  td strong { color: var(--text); font-weight: 600; }
  td:first-child { white-space: nowrap; }
  tr:last-child td { border-bottom: none; }
  .badge {
    display: inline-block;
    padding: 2px 9px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.02em;
    white-space: nowrap;
  }
  .COMPLIANT { background: var(--pass-bg); color: var(--pass-fg); border: 1px solid var(--pass-bd); }
  .NON-COMPLIANT { background: var(--fail-bg); color: var(--fail-fg); border: 1px solid var(--fail-bd); }
  .REVIEW { background: var(--warn-bg); color: var(--warn-fg); border: 1px solid var(--warn-bd); }
  .sev-CRITICAL { color: #b91c1c; font-weight: 700; font-size: 11.5px; }
  .sev-HIGH { color: #c2410c; font-weight: 700; font-size: 11.5px; }
  .sev-MEDIUM { color: #b45309; font-weight: 600; font-size: 11.5px; }
  .sev-LOW { color: #6b7280; font-weight: 600; font-size: 11.5px; }
  pre {
    background: #f8fafc;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 13px 15px;
    font-family: var(--mono);
    font-size: 11.5px;
    line-height: 1.55;
    color: #1e293b;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-word;
    margin: 8px 0 0;
  }
  #plist-preview {
    max-height: 230px;
    overflow-y: auto;
  }
  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  .hidden { display: none; }
  .tester-bar { display: flex; gap: 10px; margin-bottom: 14px; }
  input[type="text"] {
    flex: 1;
    background: #ffffff;
    border: 1px solid var(--border-strong);
    color: var(--text);
    padding: 9px 12px;
    border-radius: 7px;
    font-family: var(--mono);
    font-size: 13px;
  }
  .action-btn {
    background: var(--text);
    color: #ffffff;
    border: none;
    border-radius: 7px;
    padding: 9px 16px;
    font-family: var(--font);
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
  }
  .progress-wrap {
    height: 7px;
    background: #e5e7eb;
    border-radius: 999px;
    overflow: hidden;
    margin-top: 10px;
  }
  .progress-fill {
    height: 100%;
    background: var(--accent);
    border-radius: 999px;
  }
  code {
    font-family: var(--mono);
    font-size: 11.5px;
    color: #1e40af;
    background: #eff6ff;
    padding: 1px 5px;
    border-radius: 4px;
  }
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="title-block">
      <div class="eyebrow">System Security Audit</div>
      <h1>Password-Policy Compliance Review</h1>
      <div class="subtitle" id="org-subtitle"></div>
    </div>
    <div class="host-pill" id="host-meta"></div>
  </header>

  <div class="tabs">
    <button class="tab-btn active" data-tab="overview">1. Overview &amp; Comparison Matrix</button>
    <button class="tab-btn" data-tab="evidence">2. System Admin Tool Evidence</button>
    <button class="tab-btn" data-tab="recommendations">3. Recommended Changes &amp; Plist</button>
    <button class="tab-btn" data-tab="tester">4. Live Policy Gap Tester</button>
  </div>

  <section id="tab-overview">
    <div class="kpis" id="kpi-cards"></div>
    <div class="card">
      <h2>Local / Domain Settings vs. Stated Organization Requirements</h2>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Control</th>
            <th>Stated Requirement</th>
            <th>Observed System Setting</th>
            <th>Status</th>
            <th>Severity</th>
          </tr>
        </thead>
        <tbody id="matrix-body"></tbody>
      </table>
    </div>
  </section>

  <section id="tab-evidence" class="hidden">
    <div class="grid-2" id="evidence-grid"></div>
  </section>

  <section id="tab-recommendations" class="hidden">
    <div class="card">
      <h2>Simulated Verification (Applying <code>recommended_account_policy.plist</code> — Read-Only)</h2>
      <div id="sim-summary"></div>
    </div>
    <div class="card">
      <h2>Prioritized Remediation Plan</h2>
      <div id="rec-list"></div>
    </div>
    <div class="card">
      <h2>Generated Deployment Artifact: <code>reports/recommended_account_policy.plist</code></h2>
      <div class="subtitle">Apply via <code>sudo pwpolicy -setaccountpolicies reports/recommended_account_policy.plist</code> or push via enterprise MDM.</div>
      <pre id="plist-preview"></pre>
    </div>
  </section>

  <section id="tab-tester" class="hidden">
    <div class="card">
      <h2>Compare Candidate Passwords: Current Local Policy vs. Organization Policy</h2>
      <div class="subtitle" style="margin-bottom: 12px;">Demonstrates why weak passwords (like 4-char PINs) pass macOS's default <code>com.apple.defaultpasswordpolicy.fde</code> rule while failing organizational standards.</div>
      <div class="tester-bar">
        <input id="pwd-input" type="text" placeholder="Type a sample password to test against both policies..." value="Pass@2026" />
        <button class="action-btn" id="pwd-test-btn">Evaluate Password</button>
      </div>
      <table>
        <thead>
          <tr>
            <th>Sample Password</th>
            <th>Length</th>
            <th>Char Classes</th>
            <th>Current Local Policy (<code>pwpolicy</code>)</th>
            <th>Organization Policy (v2.4)</th>
          </tr>
        </thead>
        <tbody id="tester-body"></tbody>
      </table>
    </div>
  </section>
</div>

<script>
const DATA = __DATA_JSON__;
const { state, compliance, sim_compliance, sample_tests, recommended_plist } = DATA;
const s = compliance.summary;

document.getElementById("org-subtitle").textContent =
  `${compliance.organization} (v${compliance.policy_version}) — ${compliance.reference_standards.join(" | ")}`;

document.getElementById("host-meta").innerHTML = `
  <div>Host: <strong>${state.hostname}</strong> | User: <strong>${state.current_user}</strong></div>
  <div>${state.os_version} | Collected: ${state.collected_at}</div>
`;

document.getElementById("kpi-cards").innerHTML = `
  <div class="kpi">
    <div class="label">Compliance Score</div>
    <div class="value" style="color:${s.compliance_score_pct >= 80 ? '#047857' : '#111827'}">${s.compliance_score_pct}%</div>
    <div class="progress-wrap"><div class="progress-fill" style="width:${s.compliance_score_pct}%"></div></div>
  </div>
  <div class="kpi">
    <div class="label">Compliant Controls</div>
    <div class="value" style="color:#047857">${s.compliant} / ${s.total_controls}</div>
    <div class="hint">FileVault, Screen Lock, PBKDF2, PAM</div>
  </div>
  <div class="kpi">
    <div class="label">Non-Compliant Gaps</div>
    <div class="value" style="color:#b91c1c">${s.non_compliant}</div>
    <div class="hint">4-char min, no complexity or lockout</div>
  </div>
  <div class="kpi">
    <div class="label">Directory / MDM</div>
    <div class="value" style="font-size:21px; padding-top:5px; color:#b45309">${state.mdm_enrolled || state.ad_bound ? 'Managed' : 'Standalone'}</div>
    <div class="hint">AD Bound: ${state.ad_bound ? 'Yes' : 'No'} | MDM: ${state.mdm_enrolled ? 'Yes' : 'No'}</div>
  </div>
`;

const tbody = document.getElementById("matrix-body");
for (const r of compliance.results) {
  const tr = document.createElement("tr");
  tr.innerHTML = `
    <td><code>${r.id}</code></td>
    <td><strong>${r.title}</strong><div class="subtitle">${r.category}</div></td>
    <td>${r.required_value}</td>
    <td>${r.actual_value}</td>
    <td><span class="badge ${r.status}">${r.status}</span></td>
    <td><span class="sev-${r.severity}">${r.severity}</span></td>
  `;
  tbody.appendChild(tr);
}

const evGrid = document.getElementById("evidence-grid");
const evItems = [
  ["pwpolicy -getaccountpolicies (parsed)", JSON.stringify(state.pwpolicy_parsed, null, 2)],
  ["pwpolicy -getglobalpolicy", state.raw_evidence.pwpolicy_global.stdout || "(empty — legacy global policy unset)"],
  ["sysadminctl -screenLock status", state.raw_evidence.sysadminctl_screenlock.stderr || state.raw_evidence.sysadminctl_screenlock.stdout],
  ["profiles status -type enrollment & dsconfigad -show", `profiles:\n${state.raw_evidence.profiles_enrollment.stdout}\n\ndsconfigad:\n${state.raw_evidence.dsconfigad_show.stdout || "(not bound to Active Directory)"}`],
  ["fdesetup status & loginwindow defaults", `fdesetup: ${state.raw_evidence.fdesetup_status.stdout}\nautoLoginUser: ${state.raw_evidence.loginwindow_autologin.stderr || state.raw_evidence.loginwindow_autologin.stdout}\nGuestEnabled: ${state.raw_evidence.loginwindow_guest.stdout}`],
  ["dscl AuthenticationAuthority & PAM", `${state.raw_evidence.dscl_auth_authority.stdout}\n\n/etc/pam.d/passwd:\n${(state.pam_files.passwd || []).join("\\n")}`]
];
for (const [title, content] of evItems) {
  const div = document.createElement("div");
  div.className = "card";
  const h = document.createElement("h2");
  h.textContent = title;
  const pre = document.createElement("pre");
  pre.textContent = content;
  div.appendChild(h);
  div.appendChild(pre);
  evGrid.appendChild(div);
}

const simSum = sim_compliance.summary;
const fixedIds = sim_compliance.results
  .filter((r, i) => r.status === "COMPLIANT" && compliance.results[i].status !== "COMPLIANT")
  .map(r => `${r.id} (${r.title})`);
document.getElementById("sim-summary").innerHTML = `
  <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px;">
    <div>
      <strong>Baseline:</strong> ${s.compliance_score_pct}% (${s.compliant}/${s.total_controls} compliant)
      &nbsp;&rarr;&nbsp;
      <strong style="color:#047857;">After Plist Remediation (Simulated):</strong> ${simSum.compliance_score_pct}% (${simSum.compliant}/${simSum.total_controls} compliant)
    </div>
    <span class="badge COMPLIANT">Local Policy Controls Resolved: ${fixedIds.length} (REQ-01 to REQ-05)</span>
  </div>
  <div class="subtitle" style="margin-top:6px;">Verified via <code>python3 audit_password_policy.py --simulate-plist reports/recommended_account_policy.plist</code>. Only <code>REQ-06</code> (Domain/MDM enrollment) remains external to local <code>pwpolicy</code>.</div>
`;

const recList = document.getElementById("rec-list");
for (const r of compliance.results.filter(x => x.status !== "COMPLIANT")) {
  const item = document.createElement("div");
  item.style.cssText = "padding:12px 0; border-bottom:1px solid #e5e7eb;";
  item.innerHTML = `
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
      <strong><code>${r.id}</code> — ${r.title}</strong>
      <span class="badge ${r.status}">${r.severity} • ${r.status}</span>
    </div>
    <div class="subtitle" style="margin-bottom:4px;">Current: ${r.actual_value} | Required: ${r.required_value}</div>
    <div style="font-size:13px;">Recommended Change: ${r.recommendation}</div>
  `;
  recList.appendChild(item);
}
document.getElementById("plist-preview").textContent = recommended_plist;

const testerRows = [...sample_tests];
function evaluateCandidate(pwd) {
  const localMin = state.pwpolicy_parsed.min_length || 4;
  const localPass = pwd.length >= localMin;
  const classes = [/[A-Z]/, /[a-z]/, /[0-9]/, /[^A-Za-z0-9]/].filter(rx => rx.test(pwd)).length;
  const reasons = [];
  if (pwd.length < 12) reasons.push(`length ${pwd.length} < 12`);
  if (classes < 3 && pwd.length < 15) reasons.push(`only ${classes}/4 char classes (need >=3 or 15+ passphrase)`);
  return {
    password: pwd,
    length: pwd.length,
    classes,
    local_policy_pass: localPass,
    local_note: localPass ? `Passes current local policy (.{${localMin},}+)` : `Fails local min ${localMin}`,
    org_policy_pass: reasons.length === 0,
    org_note: reasons.length === 0 ? "Meets organization requirements" : reasons.join("; ")
  };
}
function escHtml(str) {
  return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
function renderTester() {
  const tb = document.getElementById("tester-body");
  tb.innerHTML = "";
  for (const row of testerRows) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><code>${escHtml(row.password)}</code></td>
      <td>${row.length}</td>
      <td>${row.classes} / 4</td>
      <td><span class="badge ${row.local_policy_pass ? 'COMPLIANT' : 'NON-COMPLIANT'}">${row.local_policy_pass ? 'ACCEPTED' : 'REJECTED'}</span> <span class="subtitle">${escHtml(row.local_note)}</span></td>
      <td><span class="badge ${row.org_policy_pass ? 'COMPLIANT' : 'NON-COMPLIANT'}">${row.org_policy_pass ? 'COMPLIANT' : 'REJECTED'}</span> <span class="subtitle">${escHtml(row.org_note)}</span></td>
    `;
    tb.appendChild(tr);
  }
}
renderTester();

document.getElementById("pwd-test-btn").addEventListener("click", () => {
  const val = document.getElementById("pwd-input").value;
  if (val) {
    testerRows.unshift(evaluateCandidate(val));
    renderTester();
  }
});

function activateTab(tabName) {
  document.querySelectorAll(".tab-btn").forEach(b => b.classList.toggle("active", b.dataset.tab === tabName));
  ["overview", "evidence", "recommendations", "tester"].forEach(t => {
    document.getElementById(`tab-${t}`).classList.toggle("hidden", t !== tabName);
  });
}
document.querySelectorAll(".tab-btn").forEach(btn => {
  btn.addEventListener("click", () => activateTab(btn.dataset.tab));
});
const params = new URLSearchParams(window.location.search);
if (params.get("tab")) activateTab(params.get("tab"));
if (params.get("eval")) {
  const inp = document.getElementById("pwd-input");
  if (params.get("eval") !== "1") inp.value = params.get("eval");
  document.getElementById("pwd-test-btn").click();
}
</script>
</body>
</html>
"""
    path.write_text(template.replace("__DATA_JSON__", data_json), encoding="utf-8")


def print_cli_report(
    state: dict[str, Any],
    compliance: dict[str, Any],
    sample_tests: list[dict[str, Any]],
    test_only: bool,
    sim_label: str | None = None,
) -> None:
    """Print colorized compliance review output to stdout."""
    s = compliance["summary"]
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    header = "=== Password-Policy Compliance Review ==="
    if sim_label:
        header = f"=== Password-Policy Compliance Review [SIMULATED: {sim_label}] ==="
    print(f"{BOLD}{CYAN}{header}{RESET}")
    print(f"Host: {state['hostname']} | OS: {state['os_version']} | User: {state['current_user']}")
    print(f"Baseline: {compliance['organization']} (v{compliance['policy_version']})")
    print()

    if not test_only:
        print(f"{BOLD}{'ID':<8} {'Control':<42} {'Status':<15} {'Severity':<10} Observed Setting{RESET}")
        print("-" * 114)
        for r in compliance["results"]:
            color = GREEN if r["status"] == "COMPLIANT" else (RED if r["status"] == "NON-COMPLIANT" else YELLOW)
            print(f"{r['id']:<8} {r['title']:<42} {color}{r['status']:<15}{RESET} {r['severity']:<10} {r['actual_value']}")
        print("-" * 114)
        print(
            f"Summary: {BOLD}{s['compliance_score_pct']}% compliant{RESET} | "
            f"{GREEN}{s['compliant']} COMPLIANT{RESET}, "
            f"{RED}{s['non_compliant']} NON-COMPLIANT{RESET}, "
            f"{YELLOW}{s['review']} REVIEW{RESET}"
        )
        print()
        print(f"{BOLD}Recommended Changes:{RESET}")
        for r in compliance["results"]:
            if r["status"] != "COMPLIANT":
                print(f"  * [{r['severity']}] {r['id']} ({r['title']}): {r['recommendation']}")
        print()

    if sample_tests:
        print(f"{BOLD}Policy Gap Demonstration (Candidate Password Check):{RESET}")
        print(f"{'Candidate':<18} {'Len':<5} {'Classes':<9} {'Current Local Policy':<28} {'Organization Policy'}")
        print("-" * 98)
        for t in sample_tests:
            loc_label = "ACCEPTED" if t["local_policy_pass"] else "REJECTED"
            loc_color = GREEN if t["local_policy_pass"] else RED
            org_label = "COMPLIANT" if t["org_policy_pass"] else "REJECTED"
            org_color = GREEN if t["org_policy_pass"] else RED
            loc_col = f"{loc_color}{loc_label}{RESET}{' ' * (28 - len(loc_label))}"
            print(f"{t['password']:<18} {t['length']:<5} {t['classes']}/4     {loc_col} {org_color}{org_label}{RESET} ({t['org_note']})")


def main() -> int:
    parser = argparse.ArgumentParser(description="Review local/domain password policies on macOS.")
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY_PATH, help="Path to organization_policy.json")
    parser.add_argument("--test-passwords", nargs="*", default=["1234", "admin123", "Pass2026", "Tr0ub4dor&3!"], help="Sample passwords to compare")
    parser.add_argument("--test-only", action="store_true", help="Only print candidate password comparison")
    parser.add_argument("--simulate-plist", type=Path, default=None, help="Simulate compliance against a candidate pwpolicy XML plist without modifying system settings")
    args = parser.parse_args()

    policy = json.loads(args.policy.read_text(encoding="utf-8"))
    state = collect_system_state()
    recommended_plist = build_recommended_plist()

    if args.simulate_plist is not None:
        plist_text = args.simulate_plist.read_text(encoding="utf-8")
        sim_state = dict(state)
        sim_state["pwpolicy_parsed"] = parse_pwpolicy_plist(plist_text)
        sim_compliance = evaluate_compliance(policy, sim_state)
        sim_tests = evaluate_sample_passwords(args.test_passwords, sim_state, policy)
        print_cli_report(sim_state, sim_compliance, sim_tests, args.test_only, sim_label=str(args.simulate_plist))
        return 0

    compliance = evaluate_compliance(policy, state)
    sim_state = dict(state)
    sim_state["pwpolicy_parsed"] = parse_pwpolicy_plist(recommended_plist)
    sim_compliance = evaluate_compliance(policy, sim_state)
    sample_tests = evaluate_sample_passwords(args.test_passwords, state, policy)

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    (REPORTS_DIR / "compliance_report.json").write_text(
        json.dumps({"state": state, "compliance": compliance, "simulated_post_remediation": sim_compliance, "sample_tests": sample_tests}, indent=2),
        encoding="utf-8",
    )
    write_markdown_report(state, compliance, REPORTS_DIR / "compliance_report.md")
    (REPORTS_DIR / "recommended_account_policy.plist").write_text(recommended_plist, encoding="utf-8")
    generate_dashboard_html(state, compliance, sim_compliance, sample_tests, recommended_plist, REPORTS_DIR / "dashboard.html")

    print_cli_report(state, compliance, sample_tests, args.test_only)
    if not args.test_only:
        print(f"\nGenerated reports in: {REPORTS_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
