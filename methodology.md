# Methodology

A checklist without a test loop produces folklore. Run every item the same way: name the control, pick a privilege, exercise one class of behavior, read the product's own reaction, keep the evidence.

## Rules of engagement

- Written authorization, scoped hosts, and a restore plan before the first probe.
- Prefer a lab image that matches a supported production build, with cloud connected and disconnected variants.
- Do not test against third-party tenants or customer endpoints.
- Treat crash / BSOD / service death as a finding about *availability of protection*, not as a successful "bypass toolkit."

## Privilege tiers

Record the exact token, not "admin."

| Tier | Typical token | What it is allowed to prove |
|---|---|---|
| T0 | Standard user, Session 1 | Low-priv evasion, LOLBAS, local event-log / named-pipe abuse |
| T1 | Local admin, Session 1 | Service install, driver load policy, firewall/WFP, most self-protect tests |
| T2 | SYSTEM / Session 0 | Whether SYSTEM is exempted from the product's own hooks |
| T3 | Kernel (vulnerable driver or debugger) | Callback integrity, HVCI/VBS effectiveness — not "the product is broken because ring 0 can write memory" |

Session 0 remoting (WinRM, scheduled task, PsExec-as-SYSTEM) is **not** a low-priv test. SYSTEM is often on the product's allowlist. If the only "bypass" you have is SYSTEM writing a protected path, you have not tested the user-mode attacker.

## The test loop

For each checkbox:

1. **Name the control.** Minifilter write guard, Ob callback mask, ETW consumer, uninstall token, hash cache, … One control per run.
2. **Take a baseline.** Same host, same policy, a *detected* or *blocked* analog of the behavior (for example a Win32 `CopyFile` that the product already sees).
3. **Change one variable.** API (Win32 vs native), path (DOS vs `\??\`), timing (rename after write), privilege, or parent image.
4. **Read the product oracle first.** Agent log, driver log, tray/block event, cloud alert, process still running. Internal debug prints are supporting evidence, not the oracle.
5. **Decide hold / miss / inconclusive.** Inconclusive means the oracle was off, the policy was unloaded, or you tested from an exempt token.
6. **File the evidence pack.** See below.

Do not open a writeup with "Step 1 — baseline bypass." Lead with what the product did.

## User-mode is not the gate

Commercial EDR often leaves file, registry, and SCM ACLs permissive on purpose. The kernel driver is the enforcement layer: minifilter, registry callback, object callback, WFP callout.

A candidate finding is real only if you reproduced the operation from a **non-exempt** token and watched the driver *not* stop it. Otherwise write "ACL permissive; runtime enforcement not verified" and stop.

| Claim | Usually wrong | Usually right |
|---|---|---|
| "Admins can write Program Files" | ACL screenshot | Admin write from Session 1 succeeded *and* the minifilter stayed silent |
| "The agent is not PPL" | `Get-Process` protection field | Unstripped handle rights plus a trusted-context chain that reaches self-access |
| "I can `sc stop` the service" | SCM allows STOP | Service stays down past restart-on-fail, or the anti-tamper loop does not come back |
| "I dumped a handle" | `OpenProcess` returned a handle | `GrantedAccess` still contains rights the callback should have stripped |

## Control planes

Map every test to one plane. If a run crosses two planes, split it.

| Plane | Typical hooks | What testers try to do |
|---|---|---|
| Process / thread self-protect | `ObRegisterCallbacks` | Open, dump, inject, freeze, duplicate-close, create remote thread |
| Filesystem | Minifilter / FS filter | Write, rename, delete, reparse, bind-link, mapped write, ADS |
| Registry | `CmRegisterCallbackEx` | Policy, service keys, hive load/save, AppInit / AppCert |
| Image / process-create | `PsSetCreateProcessNotifyRoutineEx` | Ghosting, herpaderping, hollowing, PPID spoof, LOLBAS |
| Load-image | `PsSetLoadImageNotifyRoutine` | Reflective / stomped modules, unsigned companions |
| Network / telemetry | WFP, firewall, TLS pin | Isolate the sensor, MITM the channel, spoof heartbeat |
| Kernel integrity | Callback tables, filter altitude, driver signature | Unload, blind, crash, BYOVD |
| Detection parsers | PE, cert, hash, entropy, cmdline | Malformed input, offset/length shaping, cache poison |
| Lifecycle | SCM, safe mode, pending rename, maintenance token | Survive reboot, uninstall without auth, race upgrade |

## Oracles

Prefer the product's own reaction, in this order:

1. Block or quarantine that the user or admin would see
2. Agent / driver log line that names the policy
3. Cloud alert or last-gasp event after isolation
4. Process / service / driver still present and enforcing
5. Only then: ETW, debugger, or a custom probe

A custom probe that says "I wrote the byte" is not a miss if the product later rolls the file back, quarantines the process, or reports the write. Wait for the product's settle time (often a few seconds for restart-on-fail, longer for cloud).

## Evidence pack

Keep enough that a second person can refute you.

- Build / file versions of agent, driver, and user-mode companion
- Policy mode (protect / detect / off), cloud connected or not
- Token: user, groups, integrity, privileges, session
- Exact API or tool name (not a screenshot of a blog)
- Product log excerpt, event ID, or block toast
- `GrantedAccess` / NTSTATUS / Win32 error, not "it worked"
- Time sync between probe and oracle
- What you did *not* prove (no kernel debugger attached, HVCI on/off, …)

## Coverage, not trophy hunting

A useful campaign finishes the matrix, including the boring holds. Track:

- Privilege × control plane × online/offline
- At least one *detected* analog per class (proves the oracle is alive)
- Negative tests: malformed input that must fail closed
- Upgrade, safe mode, and early-boot windows — most "the driver protects this" claims die there

Severity follows attacker gain, not cleverness. "I crashed the driver" is a denial-of-protection finding. "I read a secret from an unprotected process" is a confidentiality finding. "I changed one ACL" with the driver still blocking is not a finding.

## What this methodology is not

It is not a ranked exploit chain, a kernel-exploitation course, or a place to drop unpublished bugs. If you need a working PoC against a specific product, that work stays in a private tracker.
