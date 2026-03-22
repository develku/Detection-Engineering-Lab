# Detection Engineering Lab

Detection rules, Sigma rules, dashboards, and alert tuning for a Splunk-based SIEM environment. 13 detection rules mapped to MITRE ATT&CK across 5 tactics, with vendor-neutral Sigma equivalents for SIEM portability.

Built to work with the [SIEM-Detection-Lab](https://github.com/develku/SIEM-Detection-Lab) infrastructure and validated against [Attack-Simulation-Lab](https://github.com/develku/Attack-Simulation-Lab) scenarios.

## MITRE ATT&CK Coverage

| Tactic | Technique | Rule | Severity | Log Source |
|---|---|---|---|---|
| **Credential Access** | T1003.001 | [LSASS Memory Dump](detections/credential-access/lsass-memory-dump.spl) | Critical | Sysmon 10 |
| | T1003.001 | [comsvcs DLL Dump](detections/credential-access/comsvcs-dll-dump.spl) | Critical | Sysmon 1 |
| | T1003.006 | [DCSync Detection](detections/credential-access/dcsync-detection.spl) | Critical | Security 4662 |
| | T1003.003 | [NTDS Shadow Copy](detections/credential-access/ntds-shadow-copy.spl) | High | Sysmon 1 |
| **Lateral Movement** | T1570 | [PsExec Execution](detections/lateral-movement/psexec-execution.spl) | High | Sysmon 1 + Security 4624 |
| | T1021.001 | [RDP Lateral Movement](detections/lateral-movement/rdp-lateral-movement.spl) | Medium | Security 4624 |
| | T1047 | [WMI Remote Execution](detections/lateral-movement/wmi-remote-execution.spl) | High | Sysmon 1 |
| **Persistence** | T1543.003 | [New Service Created](detections/persistence/new-service-created.spl) | Medium | System 7045 |
| | T1547.001 | [Registry Run Key](detections/persistence/registry-run-key.spl) | Medium | Sysmon 13 |
| **Privilege Escalation** | T1078.002 | [Admin Group Modification](detections/privilege-escalation/admin-group-modification.spl) | High | Security 4728/4732/4756 |
| | T1053.005 | [Scheduled Task Created](detections/privilege-escalation/scheduled-task-created.spl) | Medium | Sysmon 1 |
| **Defense Evasion** | T1070.001 | [Event Log Cleared](detections/defense-evasion/event-log-cleared.spl) | Critical | Security 1102 / System 104 |
| | T1055 | [Process Injection](detections/defense-evasion/process-injection.spl) | High | Sysmon 8 |

## Sigma Rules — SIEM Portability

Every SPL detection has a matching [Sigma](https://sigmahq.io/) rule in YAML format, enabling conversion to any SIEM platform:

```bash
# Convert to Splunk SPL
sigma convert -t splunk sigma/credential-access/lsass-memory-dump.yml

# Convert to Elasticsearch
sigma convert -t elasticsearch sigma/credential-access/lsass-memory-dump.yml

# Convert to Microsoft Sentinel (KQL)
sigma convert -t microsoft365defender sigma/credential-access/lsass-memory-dump.yml
```

| Sigma Rule | Corresponding SPL |
|---|---|
| [`sigma/credential-access/`](sigma/credential-access/) | [`detections/credential-access/`](detections/credential-access/) |
| [`sigma/lateral-movement/`](sigma/lateral-movement/) | [`detections/lateral-movement/`](detections/lateral-movement/) |
| [`sigma/persistence/`](sigma/persistence/) | [`detections/persistence/`](detections/persistence/) |
| [`sigma/privilege-escalation/`](sigma/privilege-escalation/) | [`detections/privilege-escalation/`](detections/privilege-escalation/) |
| [`sigma/defense-evasion/`](sigma/defense-evasion/) | [`detections/defense-evasion/`](detections/defense-evasion/) |

## Dashboards

5 operational dashboards for Splunk (XML):

| Dashboard | Purpose |
|---|---|
| [Authentication Overview](dashboards/authentication-overview.xml) | Login patterns, failed auth, brute force indicators |
| [Endpoint Process Activity](dashboards/endpoint-process-activity.xml) | Suspicious process execution, parent-child relationships |
| [Network Connections](dashboards/network-connections.xml) | Lateral movement indicators, unusual connections |
| [Persistence Mechanisms](dashboards/persistence-mechanisms.xml) | Registry modifications, new services, scheduled tasks |
| [Alert Summary](dashboards/alert-summary.xml) | Aggregated alert view across all detection rules |

## Alert Tuning

Writing a detection rule is the first 50% — the other 50% is tuning it to work in a real environment. Untuned rules averaged a 6.5% true positive rate across these three high-volume rules, meaning analysts investigated ~236 false alerts daily. After systematic tuning:

| Rule | Alerts/Day | TP Rate | FP Reduction | Report |
|---|---|---|---|---|
| LSASS Access | 47 → 6 | 8.5% → 66.7% | -87% | [Report](tuning/lsass-access-tuning.md) |
| Brute Force | 120 → 32 | 7.5% → 28.1% | -73% | [Report](tuning/brute-force-tuning.md) |
| Service Creation | 85 → 12 | 3.5% → 25.0% | -86% | [Report](tuning/service-creation-tuning.md) |

Methodology: [Tuning Methodology](docs/tuning-methodology.md)

## Documentation

- [Detection Rules Guide](docs/detection-rules.md) — rule logic, deployment, and usage
- [Tuning Methodology](docs/tuning-methodology.md) — systematic approach to reducing false positives

## Project Structure

```
Detection-Engineering-Lab/
├── detections/              SPL detection queries by ATT&CK tactic
│   ├── credential-access/   (4 rules)
│   ├── lateral-movement/    (3 rules)
│   ├── persistence/         (2 rules)
│   ├── privilege-escalation/(2 rules)
│   └── defense-evasion/     (2 rules)
├── sigma/                   Sigma YAML equivalents (same structure)
├── dashboards/              Splunk XML dashboards (5)
├── tuning/                  Tuning reports with quantified results
└── docs/                    Detection and tuning methodology
```

## Related Projects

This lab is part of a multi-project SOC environment:

| Project | Purpose |
|---|---|
| [AD-Lab-Setup](https://github.com/develku/AD-Lab-Setup) | Windows Active Directory infrastructure |
| [SIEM-Detection-Lab](https://github.com/develku/SIEM-Detection-Lab) | Splunk SIEM deployment and log collection |
| **Detection-Engineering-Lab** (this repo) | Detection rules, dashboards, and tuning |
| [Attack-Simulation-Lab](https://github.com/develku/Attack-Simulation-Lab) | Adversary emulation and attack validation |
