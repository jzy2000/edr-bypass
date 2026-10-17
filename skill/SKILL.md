---
name: edr-bypass-testing
description: Build and run an authorized EDR evasion proof of concept from this repo only. Use when the task is to test, bypass, or assess endpoint anti-tamper, a minifilter, process protection, telemetry, or a detection parser.
---

# EDR bypass testing

Follow `AGENTS.md`. This file is the workflow. Technique text lives on the card, not here.

## Loop

1. Read `lab/local.yaml`. If it is missing, stop.
2. Load `catalog/index.yaml`. Select the ids the operator named. If none were named, run the `first_pass` list in the catalog, skipping any card with `skip: true`.
3. For each selected id, read only `cards/<id>.md`.
4. If `skip` is true or `action` is `unspecified`, write a verdict of `skipped` and continue. Do not invent steps.
5. Run the gate below. On failure, verdict is `inconclusive` and you stop that id.
6. Build the probe in a scratch directory using only `public_apis` on the card and paths from the lab contract. The worked pattern is `examples/U-01/`.
7. Run at the card's privilege. Session 0 remoting is SYSTEM. It does not satisfy T0 or T1.
8. Read the product log from the lab contract. Decide hold, miss, or inconclusive from the card's oracle.
9. If `kind` is `parser`, also answer the variant questions on the card. A fault caught by SEH is not code execution. A read that succeeds into a user-visible buffer is a different claim; file it as a separate verdict.
10. Write `verdict.json` for this id. Run `python3 scripts/check.py`.
11. Restore per `rules/restore.md` before the next id.

## Gate

Stop with `inconclusive` unless all of these are true:

- The behavior has a real entry (minifilter, load-image, create-process, registry callback, filter port, WFP, or a cache read at driver start). Zero callers is dead code, not a miss.
- You can name the feature and the channel that delivers input.
- That feature is on, and policy has been applied. An off sensor is not a bypass.
- The token is the one on the card. SYSTEM, the product's own image, and the parent of a create are exemptions. Repeat as Session 1 admin before claiming an admin bypass.
- You are not relying on a harness that skipped an upstream size or type check.

## Call sites

Before the first probe on a parser card, list callers: site, guard, what must be true to reach it, how input arrives, what protects that input. Test the row with the fewest gates. If it fails twice for the same reason, take the next row. Do not keep rewriting a blocked path.

## Verdict

One JSON object per id, matching `lab/verdict.schema.json`. `result` is `hold`, `miss`, `inconclusive`, or `skipped`. A miss names the privilege and the one variable that changed. A hold is a valid result. Record it.
