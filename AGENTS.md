# Agent entry

This repository is the only skill pack for an authorized EDR evasion test. Do not load a private skill library, a ticket tracker, or a product source tree.

## Read order

1. `rules/` — every turn.
2. `skill/SKILL.md` — when the task is to build a proof of concept or run a bypass test.
3. `catalog/index.yaml` — to choose ids. Do not open every card.
4. `cards/<id>.md` — only the id you are about to run.
5. `lab/local.yaml` — paths and the privilege fixture. If it is missing, stop and ask the operator to copy `lab/contract.example.yaml`.
6. `examples/U-01/` — only if you have never finished a card and need the pattern.

## Do not read

`archive/` is the old prose checklist. It is not a procedure. If it disagrees with a card, the card wins.

## Ready

A run is finished only when `verdict.json` validates against `lab/verdict.schema.json` and the lab is restored.

If a card has `skip: true` or `action: unspecified`, do not invent a procedure. Record `skipped` and pick another id, or stop.

## Campaign sequence

A full campaign runs in this order:

1. **Setup** (S-01 through S-05): record versions, confirm the oracle, document exempt tokens, plan HVCI columns.
2. **First pass** (the `first_pass` list in the catalog): one card from each major plane to establish baseline coverage.
3. **Deep dive**: run all cards in each plane that showed a `miss` or `inconclusive` in the first pass.
4. **Assessment gates** (A-01 through A-12): verify every finding meets the quality bar.
5. **Closeout** (Z-01 through Z-05): evidence review and vendor data scrub.
