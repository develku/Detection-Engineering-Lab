# Detection Rules

13 rules across 5 MITRE ATT&CK tactics, each in two formats: Splunk SPL (`.spl`) for direct deployment and Sigma YAML (`.yml`) for conversion to any SIEM.

Every SPL file includes inline learning notes — line-by-line explanations of what the query does and why. Open any `.spl` file and look for `# LEARNING:` comments to see how each detection works at a technical level.

## Detection Coverage

### ATT&CK Mapping

```
                    MITRE ATT&CK Coverage
┌──────────────────┬──────────────────────────────────────┐
│ Credential Access│ LSASS Dump, comsvcs DLL, DCSync,     │
│ (4 rules)        │ NTDS Shadow Copy                     │
├──────────────────┼──────────────────────────────────────┤
│ Lateral Movement │ PsExec, RDP, WMI Remote Execution    │
│ (3 rules)        │                                      │
├──────────────────┼──────────────────────────────────────┤
│ Persistence      │ New Service, Registry Run Key        │
│ (2 rules)        │                                      │
├──────────────────┼──────────────────────────────────────┤
│ Priv Escalation  │ Admin Group Modification,            │
│ (2 rules)        │ Scheduled Task Creation              │
├──────────────────┼──────────────────────────────────────┤
│ Defense Evasion  │ Event Log Cleared, Process Injection │
│ (2 rules)        │                                      │
└──────────────────┴──────────────────────────────────────┘
```

## Rule Summary

| # | Detection | ATT&CK | Tactic | Severity | Log Source |
|---|---|---|---|---|---|
| 1 | [LSASS Memory Dump](../detections/credential-access/lsass-memory-dump.spl) | T1003.001 | Credential Access | Critical | Sysmon 10 |
| 2 | [comsvcs DLL Dump](../detections/credential-access/comsvcs-dll-dump.spl) | T1003.001 | Credential Access | Critical | Sysmon 1 |
| 3 | [DCSync Detection](../detections/credential-access/dcsync-detection.spl) | T1003.006 | Credential Access | Critical | Security 4662 |
| 4 | [NTDS Shadow Copy](../detections/credential-access/ntds-shadow-copy.spl) | T1003.003 | Credential Access | High | Sysmon 1 |
| 5 | [PsExec Execution](../detections/lateral-movement/psexec-execution.spl) | T1570 | Lateral Movement | High | Sysmon 1 + Security 4624 |
| 6 | [RDP Lateral Movement](../detections/lateral-movement/rdp-lateral-movement.spl) | T1021.001 | Lateral Movement | Medium | Security 4624 |
| 7 | [WMI Remote Execution](../detections/lateral-movement/wmi-remote-execution.spl) | T1047 | Lateral Movement | High | Sysmon 1 |
| 8 | [New Service Created](../detections/persistence/new-service-created.spl) | T1543.003 | Persistence | Medium | System 7045 |
| 9 | [Registry Run Key](../detections/persistence/registry-run-key.spl) | T1547.001 | Persistence | Medium | Sysmon 13 |
| 10 | [Admin Group Modification](../detections/privilege-escalation/admin-group-modification.spl) | T1078.002 | Privilege Escalation | High | Security 4728/4732/4756 |
| 11 | [Scheduled Task Created](../detections/privilege-escalation/scheduled-task-created.spl) | T1053.005 | Privilege Escalation | Medium | Sysmon 1 |
| 12 | [Event Log Cleared](../detections/defense-evasion/event-log-cleared.spl) | T1070.001 | Defense Evasion | Critical | Security 1102 / System 104 |
| 13 | [Process Injection](../detections/defense-evasion/process-injection.spl) | T1055 | Defense Evasion | High | Sysmon 8 |

## Rule File Format

### SPL Files (.spl)

Each `.spl` file contains a header comment block with metadata and the Splunk query:

```
# Detection: [Name]
# ATT&CK: [Technique ID] — [Technique Name]
# Tactic: [Tactic Name]
# Log Source: [Source]
# Severity: [Level]
# Description: [What and why]
# False Positives: [Known FP sources]

[SPL Query]
```

### Sigma Files (.yml)

Each `.yml` file follows the [SigmaHQ standard](https://github.com/SigmaHQ/sigma):

```yaml
title: Detection Name
id: <UUID>
status: stable
level: high
description: What this detects
tags:
  - attack.tactic_name
  - attack.tXXXX
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    field: value
  condition: selection
falsepositives:
  - Known FP source
```

Sigma rules can be converted to any SIEM using [sigma-cli](https://github.com/SigmaHQ/sigma-cli):

```bash
# Convert to Splunk SPL
sigma convert -t splunk sigma/credential-access/lsass-memory-dump.yml

# Convert to Elasticsearch Query DSL
sigma convert -t elasticsearch sigma/credential-access/lsass-memory-dump.yml
```

## How to Deploy

These rules are designed for the [SIEM-Detection-Lab](https://github.com/develku/SIEM-Detection-Lab) Splunk environment but work in any Splunk instance with the right log sources.

### Option 1: Copy/Paste

1. Open a `.spl` file
2. Copy the SPL query (skip the `#` comment lines)
3. Paste into **Splunk Search & Reporting**
4. Save as **Alert** with your trigger conditions (e.g., run every 5 minutes)

Best for testing individual rules or one-off deployments.

### Option 2: Splunk CLI

Import as saved searches for scheduled execution:

```bash
/opt/splunk/bin/splunk add saved-search "LSASS Memory Dump" \
  -search "$(grep -v '^#' detections/credential-access/lsass-memory-dump.spl)" \
  -cron_schedule "*/5 * * * *" \
  -alert.severity 5
```

Best for deploying multiple rules at once or managing rules as code.

### Option 3: Sigma Conversion

Convert to any SIEM using [sigma-cli](https://github.com/SigmaHQ/sigma-cli):

```bash
# Elasticsearch
sigma convert -t elasticsearch sigma/credential-access/lsass-memory-dump.yml

# Microsoft Sentinel (KQL)
sigma convert -t microsoft365defender sigma/credential-access/lsass-memory-dump.yml
```

## After Deployment: Tuning

Every rule will generate false positives in a real environment. The [Tuning Methodology](tuning-methodology.md) guide covers the systematic approach used in this lab, and each tuning report in [`tuning/`](../tuning/) shows the full before/after analysis with quantified results.
