# Alert Tuning Report: Brute-Force / Account Lockout Detection

### What You'll Learn

- How to identify false positive sources like service accounts with expired passwords, monitoring systems, and helpdesk workflows
- How to modify SPL queries to exclude noise while preserving detection of real brute-force and password spraying attacks
- How to validate that tuning did not break detection by simulating brute-force, password spray, and credential stuffing scenarios
- How to quantify improvement with metrics and communicate the impact to SOC leadership
- How to classify attack types (brute-force vs. password spray) and assign severity based on context like source IP location

### Why Tuning Matters

Brute-force detection rules are often the highest-volume alert in a SOC, and when analysts see 120 alerts a day that are almost all false positives, they stop investigating them entirely. This creates a dangerous blind spot -- the real password spraying attack targeting 50 domain accounts gets lost in a sea of expired service account failures. Tuning is how you cut through the noise so that when a genuine brute-force or password spray alert fires, it gets the immediate attention it deserves.

## Rule Details

| Field | Value |
|---|---|
| **Rule Name** | Brute-Force Login Attempt Detected |
| **MITRE ATT&CK** | T1110.001 - Brute Force: Password Guessing |
| **Tactic** | Credential Access |
| **Severity** | High |
| **Log Source** | Windows Security Event ID 4625 (Failed Logon), 4740 (Account Lockout) |
| **Index** | `index=wineventlog` |
| **Date Tuned** | 2026-03-19 |

---

## Before Tuning

### Metrics (7-day average)

| Metric | Value |
|---|---|
| **Alerts per day** | 120 |
| **True positives per day** | 9 |
| **False positives per day** | 111 |
| **True positive rate** | 7.5% |
| **Mean time to triage** | 4 minutes per alert |
| **Daily analyst time consumed** | ~8 hours |

### Original SPL Query

```spl
index=wineventlog EventCode=4625
| bin _time span=10m
| stats count as failure_count dc(TargetUserName) as unique_accounts values(TargetUserName) as targeted_accounts by IpAddress, _time
| where failure_count >= 5
| table _time, IpAddress, failure_count, unique_accounts, targeted_accounts
```

### Problem Statement

The brute-force detection rule was generating 120 alerts per day, making it the highest-volume alert in the SOC. The vast majority (92.5%) were false positives caused by service accounts with expired passwords, monitoring systems performing health checks with cached credentials, and misconfigured applications retrying failed authentication in tight loops. Analysts had effectively stopped investigating these alerts, creating a dangerous blind spot for real brute-force and password spraying attacks.

---

## Investigation Findings

### False Positive Source Analysis

I analyzed 7 days of brute-force alerts (840 total) by source IP and targeted account:

| Source Category | Source | Alerts (7d) | % of Total | Verdict |
|---|---|---|---|---|
| Service accounts | `svc_backup`, `svc_scan`, `svc_monitor` | 336 | 40.0% | FP - Expired/rotated passwords |
| Monitoring systems | `10.0.1.50` (Nagios), `10.0.1.51` (PRTG) | 210 | 25.0% | FP - Health checks with stale creds |
| SCCM/MECM | `10.0.1.30` (SCCM server) | 126 | 15.0% | FP - Client push installation retries |
| Helpdesk activity | Various IPs | 84 | 10.0% | FP - Password reset workflows |
| **Genuine brute-force** | **Various external/unusual IPs** | **63** | **7.5%** | **TP - Real attacks** |
| **Password spraying** | **Single IP, many accounts** | **21** | **2.5%** | **TP - Real attacks** |

### Key Observations

1. **Service accounts** were the largest single source of false positives. Three accounts (`svc_backup`, `svc_scan`, `svc_monitor`) had passwords rotated on the AD side but not updated on the systems using them. Each generated 15-20 failed logon events per hour, 24/7.

2. **Monitoring systems** (Nagios and PRTG) perform WMI/DCOM health checks against domain machines every 5 minutes. When service credentials expired, each check generated a burst of 5-8 failed logons, consistently triggering the 5-failure threshold.

3. **SCCM client push** retries authentication multiple times when deploying software packages. During patching windows (Tuesdays), alert volume spiked to 200+ alerts/day.

4. **Helpdesk password resets** involve the user failing authentication 3-5 times before calling the helpdesk, then the helpdesk testing the new password. This legitimate workflow was triggering alerts.

5. **True positives** (63 alerts) included actual password guessing from a single compromised internal host (45 alerts) and external RDP brute-force attempts against an exposed jump server (18 alerts). The password spraying attempts (21 alerts) targeted 50+ accounts from a single IP with 1-2 attempts per account.

### Threshold Analysis

| Threshold | Daily Alerts | TP Rate | FP Eliminated | TP Lost |
|---|---|---|---|---|
| >= 5 failures (original) | 120 | 7.5% | baseline | baseline |
| >= 10 failures | 78 | 11.5% | 35% | 0 |
| >= 15 failures | 52 | 17.3% | 57% | 0 |
| >= 20 failures | 38 | 23.7% | 68% | 2 (password spray) |

Raising the threshold alone was insufficient -- service accounts alone generated 50+ failures per hour.

---

## Changes Applied

### Tuned SPL Query

```spl
index=wineventlog EventCode=4625
    ``` ===== TUNING: Exclude known service accounts ===== ```
| where NOT match(TargetUserName, "(?i)^(svc_backup|svc_scan|svc_monitor|svc_sccm|svc_nagios|svc_prtg|healthcheck|SYSTEM)$")
    ``` ===== TUNING: Exclude known monitoring system IPs ===== ```
| where NOT cidrmatch("10.0.1.50/32", IpAddress)
    AND NOT cidrmatch("10.0.1.51/32", IpAddress)
    AND NOT cidrmatch("10.0.1.30/32", IpAddress)
    ``` ===== TUNING: Exclude machine account failures (computer$ accounts) ===== ```
| where NOT match(TargetUserName, "\$$")
| bin _time span=10m
    ``` ===== TUNING: Differentiate brute-force vs password spray ===== ```
| stats count as failure_count
        dc(TargetUserName) as unique_accounts
        values(TargetUserName) as targeted_accounts
        values(LogonType) as logon_types
        values(SubStatus) as failure_reasons
    by IpAddress, _time
| eval attack_type=case(
    unique_accounts >= 10 AND failure_count >= 10, "Password Spray",
    unique_accounts <= 3 AND failure_count >= 10, "Brute Force",
    failure_count >= 20, "High Volume",
    failure_count >= 10, "Moderate",
    1=1, null()
    )
| where isnotnull(attack_type)
    ``` ===== TUNING: Risk scoring based on context ===== ```
| eval severity=case(
    attack_type="Password Spray", "CRITICAL",
    failure_count >= 50, "CRITICAL",
    attack_type="Brute Force" AND failure_count >= 20, "HIGH",
    NOT cidrmatch("10.0.0.0/8", IpAddress), "HIGH",
    attack_type="Brute Force", "MEDIUM",
    1=1, "LOW"
    )
| eval failure_reasons=mvjoin(failure_reasons, ", ")
| table _time, IpAddress, attack_type, severity, failure_count, unique_accounts, targeted_accounts, logon_types, failure_reasons
| sort - failure_count
```

### Summary of Changes

| Change | Rationale |
|---|---|
| Excluded 6 known service accounts by name | Eliminated 40% of FPs; these accounts are monitored separately via a dedicated service account health dashboard |
| Excluded 3 monitoring system IPs | Eliminated 25% of FPs; Nagios, PRTG, and SCCM are verified internal systems |
| Excluded machine account failures (`$` suffix) | Eliminated ~5% of FPs; computer account authentication failures are normal domain behavior |
| Raised threshold from 5 to 10 | Eliminated helpdesk workflow FPs without losing true positives |
| Added attack type classification | Differentiates brute-force (few accounts, many attempts) from password spray (many accounts, few attempts each) |
| Added severity scoring | External IPs and password spray patterns get higher severity; internal low-count events get lower |
| Added failure reason enrichment | `SubStatus` codes help analysts quickly identify locked vs. disabled vs. wrong password |

### Complementary Changes

In addition to tuning the alert rule, I implemented two supporting measures:

1. **Service Account Monitoring Dashboard**: Created a separate low-priority dashboard that tracks failed logons for excluded service accounts. This ensures we still have visibility without generating critical alerts.

2. **Remediation Request**: Submitted a ticket to the infrastructure team to update stale credentials for `svc_backup`, `svc_scan`, and `svc_monitor`. Once resolved, these accounts can be removed from the exclusion list.

---

## After Tuning

### Metrics (7-day average, post-tuning)

| Metric | Before | After | Change |
|---|---|---|---|
| **Alerts per day** | 120 | 32 | -73.3% |
| **True positives per day** | 9 | 9 | No change |
| **False positives per day** | 111 | 23 | -79.3% |
| **True positive rate** | 7.5% | 28.1% | +20.6pp |
| **Mean time to triage** | 4 min | 3 min | -25% |
| **Daily analyst time consumed** | ~8 hrs | ~1.6 hrs | -80% |

### Remaining False Positives (23/day)

The remaining 23 daily false positives come from:

| Source | Alerts/day | Plan |
|---|---|---|
| Users mistyping passwords | 12 | Acceptable -- threshold catches genuine lockout scenarios |
| VPN reconnection bursts | 6 | Evaluating VPN-specific exclusion by LogonType |
| IT admin testing | 5 | Acceptable -- low volume, quick to dismiss |

These are considered acceptable noise and will be addressed in a future tuning pass if volume increases.

### Alert Volume Trend

```
Before tuning (daily alerts):
Mon: 135 |  ███████████████████████████████████████████████████████████████████
Tue: 189 |  ██████████████████████████████████████████████████████████████████████████████████████████████ (Patch Tuesday)
Wed: 110 |  ███████████████████████████████████████████████████████
Thu: 105 |  ████████████████████████████████████████████████████
Fri:  98 |  █████████████████████████████████████████████████
Sat:  87 |  ███████████████████████████████████████████
Sun:  92 |  ██████████████████████████████████████████████

After tuning (daily alerts):
Mon:  35 |  █████████████████
Tue:  42 |  █████████████████████
Wed:  30 |  ███████████████
Thu:  28 |  ██████████████
Fri:  32 |  ████████████████
Sat:  25 |  ████████████
Sun:  29 |  ██████████████
```

---

## Validation

### Attack Simulation Re-test

| Test | Method | Detected? | Attack Type | Severity |
|---|---|---|---|---|
| Brute-force (single account) | 25 failed attempts against `admin` from single IP | Yes | Brute Force | HIGH |
| Password spray | 1-2 attempts against 30 accounts from single IP | Yes | Password Spray | CRITICAL |
| External brute-force | 15 failed attempts from non-RFC1918 IP | Yes | Brute Force | HIGH |
| Credential stuffing | 50+ attempts, 20 unique accounts | Yes | Password Spray | CRITICAL |
| Service account lockout | `svc_backup` 50 failures | No (excluded) | N/A | Visible on service account dashboard |

### Evasion Awareness

| Scenario | Detection Status |
|---|---|
| Slow brute-force (1 attempt per 15 min) | Partially detected -- may fall below 10-in-10min threshold. Addressed by a separate "low and slow" correlation rule using 24-hour windows. |
| Distributed brute-force (multiple source IPs) | Partially detected -- each IP may be below threshold. Addressed by a separate rule correlating by target account across multiple IPs. |

---

## Lessons Learned

1. **Service accounts are the silent killer of brute-force rules**. A single service account with an expired password can generate more noise than all real attacks combined. Proactively work with infrastructure teams to fix the root cause, not just exclude the symptom.

2. **Attack type classification matters**. Password spraying (many accounts, few attempts each) and brute-force (single account, many attempts) require different thresholds and severities. A flat threshold catches one but misses the other.

3. **Context drives severity**. A burst of 15 failed logins from an internal monitoring system is noise. The same burst from an external IP is a critical alert. Enriching alerts with source context dramatically improves triage efficiency.

4. **Tuning is iterative**. The first pass reduced volume by 73%, but 23 daily false positives remain. Future tuning passes will address VPN reconnection patterns and further refine thresholds based on observed attack patterns.

5. **Never exclude without alternative visibility**. Excluded service accounts are still monitored via a dedicated dashboard. If an attacker targets `svc_backup`, the SOC still has visibility -- just through a different mechanism.

6. **Document the "why" for every exclusion**. Six months from now, a new analyst will question why `svc_monitor` is excluded. The investigation notes above explain the rationale and provide the path to removal once the root cause is fixed.
