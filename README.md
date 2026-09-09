# EDR evasion testing checklist

A curated checklist and methodology for **authorized** product-security and purple-team testing of Endpoint Detection and Response (EDR) and anti-tamper controls.

This repository is a test guide, not a malware kit. It tells you **which control planes to exercise**, **what a hold vs a miss looks like**, and **what evidence to keep**. It does not publish unpublished product bugs, vendor names, ticket IDs, or exploit procedures.

The only code sample is [nt-copyfile.cpp](nt-copyfile.cpp): a small demonstration that Win32 wrappers such as `CopyFileExW` are a different monitoring surface than the native `NtCreateFile` / `NtReadFile` / `NtWriteFile` path.

## Who this is for

- Product-security engineers assessing their own EDR / EPP / anti-ransomware stack
- Purple teams running an agreed evasion-resistance campaign
- Researchers comparing public, well-known technique *classes* against a control matrix

If you do not have written authorization for the environment under test, stop.

## How to use this repo

1. Read [methodology.md](methodology.md) first. The test loop and oracle rules matter more than any single technique.
2. Work [CHECKLIST.md](CHECKLIST.md) top to bottom, or pick a control plane (self-protect, minifilter, telemetry, …).
3. Use [techniques.md](techniques.md) when a checkbox needs more context.
4. Cite public sources from [references.md](references.md). Do not paste internal writeups into a fork.

## What "pass" means

A control **holds** when the product still detects, blocks, or contains the *class* of behavior after you change API, path, timing, or privilege. A control **misses** when the same outcome (write, inject, unload, isolate, persist) succeeds and the product stays quiet or dies.

User-mode ACLs, missing PPL, and "admin can stop a service" are not findings by themselves. The kernel hooks, replay/restart logic, and cloud channel are the gates that actually matter. See [methodology.md](methodology.md#user-mode-is-not-the-gate).

## Scope

| In scope | Out of scope |
|---|---|
| Endpoint EDR / EPP / anti-tamper resistance | Cloud IAM, SaaS IDP, CI, tenant isolation |
| Technique *classes* that are already public | Unpublished 0-days, vendor-specific IOCTLs, internal IDs |
| Oracles, evidence, coverage | Ready-to-run exploit PoCs and payloads |
| Authorized lab / owned product | Third-party production tenants |

## Repo layout

| Path | Purpose |
|---|---|
| [CHECKLIST.md](CHECKLIST.md) | Master checkbox list, grouped by control plane |
| [methodology.md](methodology.md) | Test loop, privilege tiers, oracles, evidence pack |
| [techniques.md](techniques.md) | Why each class exists and what to record |
| [references.md](references.md) | Public papers, talks, and research tools |
| [CONTRIBUTING.md](CONTRIBUTING.md) | What belongs here and what must stay out |
| [nt-copyfile.cpp](nt-copyfile.cpp) | Native-API copy vs hooked Win32 copy |

## Ethics

Use this material only against systems you own or are contracted to test. Publishing a checklist of public technique classes is not permission to attack anyone else's product, customers, or lab.
