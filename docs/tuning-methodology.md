# Alert Tuning Methodology

Alert tuning is what separates a SOC analyst from someone who just deploys a SIEM. This document explains the methodology used to tune detection rules in this lab, with quantified before/after results.

## Why Tuning Matters

A detection rule that fires 100 times a day with a 5% true positive rate wastes analyst time and erodes trust in the alert pipeline. Effective tuning reduces noise while preserving the ability to catch real threats.

**Goal:** Maximise true positive rate while maintaining detection capability.

## The Tuning Workflow

```
┌──────────┐    ┌─────────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│  Alert    │───▶│ Investigate │───▶│ Classify │───▶│   Tune   │───▶│ Validate │
│  Fires    │    │ (context)   │    │ (TP/FP)  │    │ (exclude)│    │ (re-test)│
└──────────┘    └─────────────┘    └──────────┘    └──────────┘    └──────────┘
```

### Step 1: Observe

Let the rule run for at least 1 week before tuning. Collect baseline data:
- Total alert volume per day
- Distribution of triggering sources
- Time-of-day patterns

### Step 2: Investigate

For each alert, determine:
- **True Positive (TP):** Actual malicious or suspicious activity
- **False Positive (FP):** Legitimate activity that matches the rule
- **Benign True Positive (BTP):** Real activity that matches the rule but is expected (e.g., admin tools)

### Step 3: Classify FP Sources

Group false positives by root cause:
- Security tools scanning monitored processes (e.g., EDR accessing LSASS)
- Scheduled maintenance tasks (e.g., Windows Update creating services)
- Monitoring agents (e.g., SCCM client, management tools)

### Step 4: Tune

Apply exclusions for validated FP sources. Rules for safe tuning:

1. **Exclude by full path, not filename** — `*\MsMpEng.exe` is safer than just `MsMpEng`
2. **Verify the process is digitally signed** before whitelisting
3. **Never exclude based on user account alone** — accounts can be compromised
4. **Document every exclusion** with justification
5. **Keep the original query** alongside the tuned version for comparison

### Step 5: Validate

After tuning, re-run the attack simulation to confirm the rule still detects real threats:
```
Atomic Red Team test → Wait 60 seconds → Verify alert fires
```

If the alert doesn't fire after tuning, the exclusion is too broad — roll back and refine.

## Tuning Report Template

Each tuned rule in this lab has a report in the [tuning/](../tuning/) directory following this structure:

```markdown
# Tuning Report: [Rule Name]

## Rule Details
- Detection, ATT&CK mapping, SIEM, date

## Before Tuning
- Alerts/day, TP rate, FP sources

## Investigation
- What was analysed, how FPs were identified

## Changes Applied
- Original vs. tuned query
- Exclusions added with justification

## After Tuning
- Alerts/day, TP rate, FP reduction percentage
- Detection capability status

## Validation
- Atomic Red Team test results post-tuning

## Lessons Learned
- Transferable insights
```

## Tuning Results Summary

| Rule | Before (alerts/day) | After (alerts/day) | FP Reduction | TP Rate (after) | Details |
|---|---|---|---|---|---|
| LSASS Memory Access | 47 | 6 | 87% | 66.7% | [Report](../tuning/lsass-access-tuning.md) |
| Brute Force Detection | 120 | 32 | 73% | 56.3% | [Report](../tuning/brute-force-tuning.md) |
| New Service Created | 85 | 12 | 86% | 58.3% | [Report](../tuning/service-creation-tuning.md) |

## Key Principles

1. **Tune based on evidence, not assumptions.** Analyse at least 1 week of data before making changes.
2. **Preserve detection capability.** Every tuning change must be validated with a re-test.
3. **Document everything.** Future analysts (including future you) need to understand why exclusions exist.
4. **Review tuning quarterly.** Exclusions that were valid 6 months ago may no longer be appropriate.
5. **Track metrics.** Quantified improvement proves the value of tuning work.
