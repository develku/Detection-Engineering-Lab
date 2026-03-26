# Detection Engineering Lab

Three high-volume detection rules averaged a 6.5% true positive rate out of the box. Analysts would have investigated ~236 false alerts daily. After systematic tuning: 73-87% fewer false positives, zero true positives lost, and analyst triage time cut from ~20 hours/day to under 3 hours across the three rules.

This repo contains 13 Splunk SPL detection rules mapped to MITRE ATT&CK across 5 tactics, vendor-neutral Sigma equivalents for any SIEM, 5 operational dashboards, and documented tuning reports with full before/after metrics.

Built for the [SIEM-Detection-Lab](https://github.com/develku/SIEM-Detection-Lab) Splunk environment. Validated against [Attack-Simulation-Lab](https://github.com/develku/Attack-Simulation-Lab) adversary simulations.

## What This Demonstrates

- **87% fewer false positives** — LSASS access rule tuned from 47 alerts/day to 6, with TP rate rising from 8.5% to 66.7%
- **Zero detection gaps** — every tuned rule re-validated against Atomic Red Team tests and manual evasion attempts
- **~17 hours/day of analyst time recovered** — across three rules, by replacing noise with high-confidence alerts
- **13 detections, any SIEM** — SPL for Splunk, Sigma YAML for Elasticsearch, Sentinel, or any platform sigma-cli supports

## Alert Tuning Results

Writing a detection rule is the first 50% — tuning it to work in a real environment is the other 50%. Untuned rules generate noise that analysts learn to ignore, and that is how real attacks get missed.

| Rule | Alerts/Day | TP Rate | FP Reduction | Report |
|---|---|---|---|---|
| LSASS Access | 47 → 6 | 8.5% → 66.7% | -87% | [Report](tuning/lsass-access-tuning.md) |
| Brute Force | 120 → 32 | 7.5% → 28.1% | -73% | [Report](tuning/brute-force-tuning.md) |
| Service Creation | 85 → 12 | 3.5% → 25.0% | -86% | [Report](tuning/service-creation-tuning.md) |

Each tuning report covers the full process: 7-day alert analysis, false positive source categorization, the tuned SPL query with rationale for every exclusion, attack simulation re-testing, and evasion testing to verify exclusions can't be bypassed.

Methodology: [Tuning Methodology](docs/tuning-methodology.md)

## MITRE ATT&CK Coverage

13 rules across 5 tactics:

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

Every SPL file includes inline `# LEARNING:` comments explaining each query component — what it does, why it matters, and how attackers exploit the technique being detected.

Full rule documentation: [Detection Rules Guide](docs/detection-rules.md)

## Sigma Rules

Every SPL detection has a matching [Sigma](https://sigmahq.io/) rule in YAML format. Sigma is the vendor-neutral standard for detection rules — write once, convert to any SIEM:

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

## Prerequisites

- **Splunk** (or any SIEM via Sigma conversion)
- **Sysmon** on endpoints with Event IDs 1 (process creation), 8 (CreateRemoteThread), 10 (ProcessAccess), and 13 (RegistryEvent) enabled
- **Windows Security logs** forwarded to Splunk — Event IDs 1102, 4624, 4625, 4662, 4728, 4732, 4756
- **Windows System logs** forwarded to Splunk — Event IDs 104, 7045
- **[sigma-cli](https://github.com/SigmaHQ/sigma-cli)** (optional, for converting Sigma rules to non-Splunk SIEMs)

The [SIEM-Detection-Lab](https://github.com/develku/SIEM-Detection-Lab) covers the full Splunk deployment and log collection setup.

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

This repo is part of a multi-project SOC environment:

| Project | Purpose |
|---|---|
| [AD-Lab-Setup](https://github.com/develku/AD-Lab-Setup) | Windows Active Directory infrastructure |
| [SIEM-Detection-Lab](https://github.com/develku/SIEM-Detection-Lab) | Splunk SIEM deployment and log collection |
| **Detection-Engineering-Lab** (this repo) | Detection rules, dashboards, and tuning |
| [Attack-Simulation-Lab](https://github.com/develku/Attack-Simulation-Lab) | Adversary emulation and attack validation |
