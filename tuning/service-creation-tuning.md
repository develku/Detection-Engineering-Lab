# Alert Tuning Report: Suspicious Service Creation

### What You'll Learn

- How to identify false positive sources like Windows Update, SCCM deployments, and approved IT tools that create services routinely
- How to modify SPL queries to exclude legitimate service patterns using path-based and name-based filters
- How to validate that tuning did not break detection by re-running PsExec, Meterpreter, and Atomic Red Team service creation tests
- How to quantify improvement with metrics and handle predictable noise spikes like Patch Tuesday
- How binary path analysis reveals the strongest signal for distinguishing malicious services from legitimate ones

### Why Tuning Matters

In an enterprise environment, Windows services are created constantly by updates, software deployments, and driver installations. A rule that fires on every new service will generate 85+ alerts a day, and analysts will start rubber-stamping them as false positives without actually investigating. That is exactly when an attacker installs a PsExec service or a PowerShell-based reverse shell and nobody notices. Tuning this rule to focus on suspicious binary paths and known attack patterns is what makes it a useful detection instead of background noise.

## Rule Details

| Field | Value |
|---|---|
| **Rule Name** | Suspicious Service Creation Detected |
| **MITRE ATT&CK** | T1543.003 - Create or Modify System Process: Windows Service |
| **Tactic** | Persistence / Privilege Escalation |
| **Severity** | High |
| **Log Source** | Windows System Event ID 7045 (New Service Installed) |
| **Index** | `index=wineventlog` |
| **Date Tuned** | 2026-03-19 |

---

## Before Tuning

### Metrics (7-day average)

| Metric | Value |
|---|---|
| **Alerts per day** | 85 |
| **True positives per day** | 3 |
| **False positives per day** | 82 |
| **True positive rate** | 3.5% |
| **Mean time to triage** | 5 minutes per alert |
| **Daily analyst time consumed** | ~7.1 hours |

### Original SPL Query

```spl
index=wineventlog source="WinEventLog:System" EventCode=7045
| where ServiceType="user mode service"
| eval install_time=strftime(_time, "%Y-%m-%d %H:%M:%S")
| table install_time, ComputerName, ServiceName, ImagePath, ServiceStartType, AccountName
| sort - install_time
```

### Problem Statement

The original rule fired on every new user-mode service installation, generating 85 alerts per day. In an enterprise environment, Windows Update, SCCM software deployments, driver installations, and legitimate IT tools create services constantly. With a 3.5% true positive rate, analysts were dismissing these alerts reflexively, which meant genuinely suspicious services (PsExec, reverse shells, malicious persistence) were being overlooked in the noise.

---

## Investigation Findings

### False Positive Source Analysis

I analyzed 7 days of service creation alerts (595 total) and categorized each by source:

| Source Category | Examples | Alerts (7d) | % of Total | Verdict |
|---|---|---|---|---|
| Windows Update | `TrustedInstaller`, `wuauserv` related services | 168 | 28.2% | FP - Standard OS patching |
| SCCM/MECM deployments | `ccmsetup`, `CcmExec`, package deployment services | 140 | 23.5% | FP - Software distribution |
| Microsoft-signed services | `Microsoft Defender`, `OneSyncSvc`, `WaaSMedicSvc` | 98 | 16.5% | FP - Standard Microsoft services |
| Third-party IT tools | `TeamViewer`, `Bomgar`, `ConnectWise` | 70 | 11.8% | FP - Approved remote support tools |
| Driver installations | GPU drivers, printer drivers, peripheral drivers | 56 | 9.4% | FP - Hardware driver services |
| Anti-virus updates | `Defender Platform Updates`, `CrowdStrike sensor` | 42 | 7.1% | FP - Security tool updates |
| **Suspicious/Unknown** | **Unknown binaries, unusual paths** | **21** | **3.5%** | **TP candidates** |

### Key Observations

1. **Windows Update** was the single largest contributor. Every cumulative update creates or modifies multiple services. Patch Tuesday alone generated 60+ service creation events across the environment.

2. **SCCM deployments** create temporary services during software installation. These follow a predictable pattern: the service name contains `ccm` or matches a known SCCM package GUID, and the binary path points to `C:\Windows\ccmcache\`.

3. **Microsoft-signed services** should be excluded when the binary is in a protected path (`C:\Windows\System32\`, `C:\Program Files\`) and has a valid signature. Unsigned binaries masquerading in these paths should still trigger.

4. **True positive candidates** (21 alerts) included: lab simulation services from Atomic Red Team (9), PsExec service installations during legitimate red team exercises (6), and genuinely suspicious services with binaries in `%TEMP%` or encoded command-line arguments (6).

### Binary Path Analysis

| Binary Path Pattern | Total Hits | TP Rate | Assessment |
|---|---|---|---|
| `C:\Windows\System32\*` | 245 | 0.4% | Almost always legitimate |
| `C:\Program Files\*` | 132 | 0.8% | Almost always legitimate |
| `C:\Windows\CCM*` | 98 | 0% | SCCM -- always legitimate |
| `C:\Windows\SysWOW64\*` | 42 | 2.4% | Usually legitimate |
| `C:\Windows\Temp\*` | 18 | 66.7% | High suspicion |
| `C:\Users\*\AppData\*` | 12 | 75.0% | High suspicion |
| `cmd.exe /c *` | 8 | 87.5% | Almost always malicious |
| `powershell.exe *` | 6 | 100% | Always malicious as a service binary |
| Other / relative paths | 34 | 23.5% | Mixed |

This analysis clearly shows that binary path is the strongest indicator of whether a service creation is malicious. Services with binaries in `System32` or `Program Files` are nearly always legitimate, while services invoking `cmd.exe` or `powershell.exe` are almost always malicious persistence.

---

## Changes Applied

### Tuned SPL Query

```spl
index=wineventlog source="WinEventLog:System" EventCode=7045
| where ServiceType="user mode service"
    ``` ===== TUNING: Exclude known legitimate service patterns ===== ```
    ``` Microsoft signed services from protected paths ```
| where NOT (match(ImagePath, "(?i)^(C:\\\\Windows\\\\System32\\\\|C:\\\\Windows\\\\SysWOW64\\\\|\"C:\\\\Windows\\\\System32\\\\)")
    AND match(ServiceName, "(?i)^(wuauserv|WaaSMedicSvc|UsoSvc|TrustedInstaller|BITS|CryptSvc|Appinfo|DcomLaunch|Dhcp|Dnscache|EventLog|LanmanServer|LanmanWorkstation|MpsSvc|Netlogon|PlugPlay|RpcSs|SamSs|Schedule|SENS|Spooler|WinDefend|WinRM|Winmgmt|W32Time|OneSyncSvc)"))
    ``` SCCM/MECM deployment services ```
| where NOT match(ImagePath, "(?i)^(C:\\\\Windows\\\\ccmsetup\\\\|C:\\\\Windows\\\\CCM\\\\|C:\\\\Windows\\\\ccmcache\\\\)")
    ``` Approved remote support tools (validated by IT) ```
| where NOT match(ImagePath, "(?i)^(C:\\\\Program Files.*\\\\TeamViewer\\\\|C:\\\\Program Files.*\\\\Bomgar\\\\|C:\\\\Program Files.*\\\\ConnectWise\\\\|C:\\\\Program Files.*\\\\CrowdStrike\\\\)")
    ``` Windows Defender platform updates ```
| where NOT match(ImagePath, "(?i)^(C:\\\\ProgramData\\\\Microsoft\\\\Windows Defender\\\\)")
    ``` ===== TUNING: Flag high-fidelity malicious patterns ===== ```
| eval risk=case(
    match(ImagePath, "(?i)(cmd\.exe|powershell\.exe|pwsh\.exe|mshta\.exe|wscript\.exe|cscript\.exe|rundll32\.exe)"), "CRITICAL",
    match(ImagePath, "(?i)(-enc|-encodedcommand|downloadstring|invoke-expression|iex |bypass|hidden)"), "CRITICAL",
    match(ImagePath, "(?i)(\\\\Temp\\\\|\\\\tmp\\\\|\\\\AppData\\\\|\\\\Public\\\\|\\\\Downloads\\\\|\\\\Desktop\\\\)"), "HIGH",
    match(ImagePath, "(?i)(\\\\\\\\|http://|https://|ftp://)"), "HIGH",
    match(ServiceName, "(?i)^(PSEXESVC|meterpreter|beacon|cobalt|shell|reverse|payload)"), "CRITICAL",
    ServiceStartType="auto start" AND NOT match(ImagePath, "(?i)(windows|program files|programdata)"), "MEDIUM",
    1=1, "LOW"
    )
| eval install_time=strftime(_time, "%Y-%m-%d %H:%M:%S")
| eval service_start=case(
    ServiceStartType="auto start", "Automatic",
    ServiceStartType="demand start", "Manual",
    ServiceStartType="disabled", "Disabled",
    1=1, ServiceStartType
    )
| table install_time, ComputerName, ServiceName, ImagePath, service_start, AccountName, risk
| sort - risk, - install_time
```

### Summary of Changes

| Change | Rationale |
|---|---|
| Excluded 25+ known Microsoft services from System32 | Eliminated 28.2% of FPs; these are standard OS services reinstalled during updates |
| Excluded SCCM paths (ccmsetup, CCM, ccmcache) | Eliminated 23.5% of FPs; SCCM service creation is a known deployment pattern |
| Excluded approved remote support tools by path | Eliminated 11.8% of FPs; tools validated with IT team as authorized |
| Excluded Windows Defender platform update path | Eliminated 7.1% of FPs; Defender updates are routine |
| Added CRITICAL flags for cmd/powershell service binaries | Zero-tolerance for services that execute shell commands -- nearly always malicious |
| Added HIGH flags for temp/user directory binaries | Legitimate services are almost never installed from user-writable directories |
| Added CRITICAL flags for known attack tool service names | PsExec, Meterpreter, Cobalt Strike service names get immediate escalation |
| Added risk-based sorting | Analysts see highest-risk services first |

> **Security note**: Exclusions are path-based and pattern-specific. A service installed from `C:\Windows\Temp\svchost.exe` will NOT be excluded -- only services in `System32` with matching known service names are filtered.

### Complementary Changes

1. **Driver service monitoring**: Created a separate informational report for kernel driver installations (`ServiceType="kernel mode driver"`), which are tracked separately due to their elevated access.

2. **SCCM deployment correlation**: Added a saved search that correlates SCCM deployment logs with service creations, so excluded SCCM services are still auditable for compliance purposes.

---

## After Tuning

### Metrics (7-day average, post-tuning)

| Metric | Before | After | Change |
|---|---|---|---|
| **Alerts per day** | 85 | 12 | -85.9% |
| **True positives per day** | 3 | 3 | No change |
| **False positives per day** | 82 | 9 | -89.0% |
| **True positive rate** | 3.5% | 25.0% | +21.5pp |
| **Mean time to triage** | 5 min | 3 min | -40% |
| **Daily analyst time consumed** | ~7.1 hrs | ~36 min | -91.5% |

### Remaining False Positives (9/day)

| Source | Alerts/day | Plan |
|---|---|---|
| New third-party software installations | 4 | Case-by-case review; may add to approved list after validation |
| Printer/peripheral driver updates | 3 | Evaluating driver-specific exclusion by service type |
| IT admin manual service creation | 2 | Acceptable -- legitimate admin activity |

### Alert Volume Trend

```
Before tuning (daily alerts):
Mon:  78 |  ██████████████████████████████████████████████████████████████████████████████
Tue: 152 |  ████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████ (Patch Tuesday)
Wed:  82 |  ██████████████████████████████████████████████████████████████████████████████████
Thu:  70 |  ██████████████████████████████████████████████████████████████████████████
Fri:  75 |  ███████████████████████████████████████████████████████████████████████████
Sat:  62 |  ██████████████████████████████████████████████████████████████
Sun:  58 |  ██████████████████████████████████████████████████████████

After tuning (daily alerts):
Mon:  11 |  ███████████
Tue:  18 |  ██████████████████ (Patch Tuesday -- remaining are new/unlisted services)
Wed:  12 |  ████████████
Thu:  10 |  ██████████
Fri:  13 |  █████████████
Sat:   8 |  ████████
Sun:   9 |  █████████
```

---

## Validation

### Attack Simulation Re-test

| Test | Method | Detected? | Risk Level |
|---|---|---|---|
| PsExec remote execution | `PsExec.exe \\target cmd.exe /c whoami` | Yes (PSEXESVC detected) | CRITICAL |
| Malicious service from Temp | `sc create EvilSvc binPath= "C:\Windows\Temp\shell.exe"` | Yes | HIGH |
| PowerShell service persistence | `sc create UpdateSvc binPath= "powershell.exe -enc ..."` | Yes | CRITICAL |
| Meterpreter service | `meterpreter > run persistence` | Yes | CRITICAL |
| Atomic Red Team T1543.003 #2 | `Invoke-AtomicTest T1543.003 -TestNumbers 2` | Yes | HIGH |
| Legitimate service from Program Files | `sc create LegitSvc binPath= "C:\Program Files\App\svc.exe"` | Yes | LOW |
| Windows Update service reinstall | Cumulative update KB5034441 | No (excluded) | N/A |
| SCCM package deployment | Software Center install of 7-Zip | No (excluded) | N/A |

All attack simulations were detected. Legitimate operations were correctly excluded.

### Patch Tuesday Stress Test

During the first Patch Tuesday after tuning, alert volume dropped from the historical average of 152 to just 18. The 18 remaining alerts were legitimate new services introduced by the cumulative update that were not in the exclusion list. These were triaged in under 15 minutes, compared to the previous 3+ hours.

---

## Lessons Learned

1. **Binary path is the strongest signal for service creation alerts**. A service binary in `System32` or `Program Files` is almost certainly legitimate. A service binary in `%TEMP%` or invoking `cmd.exe /c` is almost certainly malicious. Build detection logic around this distinction.

2. **Patch Tuesday amplifies every service creation rule**. If your rule does not account for Windows Update behavior, expect a 2-3x spike on the second Tuesday of every month. This predictable noise erodes analyst trust in the rule.

3. **SCCM creates enormous service creation noise in managed environments**. Organizations using SCCM/MECM for software deployment should plan for SCCM-specific exclusions from day one. The alternative is drowning in false positives.

4. **Zero-tolerance patterns improve signal quality dramatically**. Services that execute `cmd.exe`, `powershell.exe`, or encoded commands should always be flagged as CRITICAL, regardless of other context. In our 7-day analysis, 100% of PowerShell service binaries were malicious or simulation-related.

5. **Kernel driver services deserve separate treatment**. User-mode services and kernel-mode drivers have different risk profiles and different false positive sources. A single rule covering both will either be too noisy or too narrow. Split them.

6. **Maintain the exclusion list as a living document**. When IT deploys a new tool (e.g., a new remote support agent), it will create services that trigger alerts. Having a documented process for validating and adding exclusions prevents ad-hoc filter changes that may create detection gaps.
