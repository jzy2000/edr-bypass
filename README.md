# EDR evasion testing checklist

A curated checklist and methodology for **authorized** product-security and purple-team testing of Endpoint Detection and Response (EDR) and anti-tamper controls.

This repository is a test guide, not a malware kit. It tells you **which control planes to exercise**, **what a hold vs a miss looks like**, and **what evidence to keep**. It does not publish unpublished product bugs, vendor names, ticket IDs, or exploit procedures.

[nt-copyfile.cpp](nt-copyfile.cpp) is a small demonstration that Win32 wrappers such as `CopyFileExW` are a different monitoring surface than the native `NtCreateFile` / `NtReadFile` / `NtWriteFile` path.

## Who this is for

- Product-security engineers assessing their own EDR / EPP / anti-ransomware stack
- Purple, red teams running an agreed evasion-resistance campaign
- Researchers comparing public, well-known technique *classes* against a control matrix

If you do not have written authorization for the environment under test, stop.

## How to use this repo

1. Read [methodology.md](methodology.md) first. The test loop and oracle rules matter more than any single technique.
2. Work [CHECKLIST.md](CHECKLIST.md) top to bottom, or pick a control plane (self-protect, minifilter, telemetry, …).
3. Use [techniques.md](techniques.md) when a checkbox needs more context.
4. Cite public sources from [references.md](references.md). Do not paste internal writeups into a fork.

## Ethics

Use this material only against systems you own or are contracted to test. Publishing a checklist of public technique classes is not permission to attack anyone else's product, customers, or lab.
