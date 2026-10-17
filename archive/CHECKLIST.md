# Checklist

Work top to bottom or jump a plane. Each item is one testable claim. Read [methodology.md](methodology.md) before ticking anything. Privilege: **T0** standard user, **T1** local admin Session 1, **T2** SYSTEM / Session 0, **T3** kernel / debugger. "Hold" means the product still detects, blocks, or contains. "Miss" means the outcome lands and the product stays quiet or dies.

Do not treat a SYSTEM or parent-process exemption as a T0 miss.

## 0. Campaign setup

- [ ] **S-01** Written scope, restore snapshot, and a known-good *detected* analog for each plane you will touch.
- [ ] **S-02** Record agent, driver, companion DLL, and OS build. Policy mode and cloud connected / disconnected.
- [ ] **S-03** Confirm the oracle is alive: a boring Win32 write / create / service stop that the product already reacts to.
- [ ] **S-04** Identify exempt tokens (SYSTEM, own image, parent of a create). Do not use them as the only attacker.
- [ ] **S-05** HVCI / VBS / Memory Integrity on and off as two columns, not one blended run.

## 1. Userland hooks and native API

- [ ] **U-01** Win32 file copy (`CopyFileExW` and friends) vs native `NtCreateFile` / `NtReadFile` / `NtWriteFile` ([nt-copyfile.cpp](nt-copyfile.cpp)). **T0/T1.** Hold = both visible. Miss = only Win32.
- [ ] **U-02** Same bytes via `WriteFile`, `NtWriteFile`, and a mapped view (`MapViewOfFile`). **T0/T1.** Hold = mapped write still hits content / tamper sensors.
- [ ] **U-03** `\??\` and `\\?\` paths vs `C:\` DOS paths for a protected file. **T1.**
- [ ] **U-04** Rename / link / hardlink / `NtSetInformationFile` instead of overwrite. **T1.**
- [ ] **U-05** Direct / indirect syscalls and a restored clean `ntdll` stub for a monitored API (`NtAllocateVirtualMemory`, `NtCreateThreadEx`, `NtWriteVirtualMemory`). **T0/T1.** Hold = kernel or secondary sensor still fires.
- [ ] **U-06** AMSI patch or unhook. **T0.** Hold = script still blocked or a non-AMSI sensor fires.
- [ ] **U-07** ETW user-mode silence (`EtwEventWrite` patch, session disable, Threat-Intelligence tamper). **T1.** Hold = kernel ETW or a non-ETW sensor remains.
- [ ] **U-08** Sleep / stack / heap obfuscation around a long-running implant. **T0.** Hold = periodic memory or behavior scan still sees it.

## 2. Process creation and injection

- [ ] **P-01** Ordinary `CreateProcess` of a known-bad or known-interesting image (oracle check). **T0.**
- [ ] **P-02** Process ghosting (delete-pending + image section). **T1.** Hold = create blocked or `DeletePending` / missing file alerted.
- [ ] **P-03** Process herpaderping (section vs on-disk mismatch). **T1.**
- [ ] **P-04** Process hollowing of a trusted image. **T1.**
- [ ] **P-05** Doppelgänging / transacted image where the OS still allows it. **T1.**
- [ ] **P-06** PPID spoof and PEB command-line spoof vs what the product logs. **T0/T1.**
- [ ] **P-07** Remote thread / `NtCreateThreadEx` into an arbitrary process. **T1.**
- [ ] **P-08** APC / early-bird / threadless class into a peer. **T1.**
- [ ] **P-09** Reflective load or module stomp of a signed DLL. **T1.**
- [ ] **P-10** Injection into a *sibling* (UI, updater, helper) that the driver may treat as own-process. **T1.** Hold = sibling is not a free allowlist pass.
- [ ] **P-11** `CREATE_SUSPENDED` of the product's own image by a non-product parent. **T1.** Hold = parent handle is stripped or create is refused.

## 3. DLL, COM, and load-order

- [ ] **D-01** Plant a missing import next to the agent or a sibling binary. **T1.**
- [ ] **D-02** Phantom / known-sideload DLL names (`winhttp` class, graphics stack, crash helper). **T1.**
- [ ] **D-03** COM `InprocServer32` hijack under HKCU that a privileged process will load. **T0/T1.**
- [ ] **D-04** Performance-counter `Library` DLL on a service the product does not protect. **T1.**
- [ ] **D-05** `AppInit_DLLs` / `AppCertDlls` if those keys are writable and unhooked. **T1.**
- [ ] **D-06** Unsigned or swapped companion DLL next to the agent. **T1.** Hold = driver refuses the companion.

## 4. Self-protect: process, thread, handle

- [ ] **H-01** `OpenProcess(PROCESS_ALL_ACCESS)` on the agent from T1. Record `GrantedAccess`. Hold = invasive bits stripped.
- [ ] **H-02** Leftover `PROCESS_CREATE_THREAD`. Hold = cannot run code or `ExitProcess` in the agent.
- [ ] **H-03** Leftover `PROCESS_VM_READ`. Hold = secrets not sitting in cleartext, or read is blocked.
- [ ] **H-04** Leftover `PROCESS_DUP_HANDLE` / duplicate-close of the agent's handles. Hold = process stays up.
- [ ] **H-05** Leftover `PROCESS_SET_INFORMATION` / quota / job-object kill. **T1.**
- [ ] **H-06** `OpenThread` mask vs process mask (suspend, set-context, impersonate). **T1.**
- [ ] **H-07** Steal a pre-existing handle from an exempt process (csrss, services) and reuse it. **T2.**
- [ ] **H-08** Dump or scrape agent memory for keys, tokens, DB material. **T1.** Hold = no handle, or material is not recoverable.
- [ ] **H-09** Unload or unmap the product's injected user-mode sensor DLL. **T1.** Hold = capture / hook returns or process is contained.
- [ ] **H-10** CPU priority / freeze / working-set starve of the agent. **T1.** Hold = watchdog or kernel path still enforces.

## 5. PPL, ELAM, signature

- [ ] **L-01** Record whether the agent is PPL and at which signer. "Not PPL" alone is not a miss.
- [ ] **L-02** Chain test: leftover handle right **and** sibling hijack **and** own-process exemption. **T1.**
- [ ] **L-03** Driver checks the user-mode client's Authenticode chain, not only a file name or subject string. **T1.**
- [ ] **L-04** Driver checks its own image / companion after upgrade and after a pending-rename. **T1.**
- [ ] **L-05** ELAM / early-launch path: can an unsigned service in the Filter group start first and occupy the port? **T1** + reboot.

## 6. Minifilter and filesystem

- [ ] **F-01** Write / delete / rename of install dir and data dir from T1. Hold = STATUS_ACCESS_DENIED or equivalent from the filter, not only the ACL.
- [ ] **F-02** Same operations from T0 (must hold) and from T2 (document if SYSTEM is exempt).
- [ ] **F-03** Altitude tamper / instance detach / second filter that shadows the product. **T1/T3.**
- [ ] **F-04** Reparse, junction, or bind link on a *parent* of a protected path ([EDR-Redir](https://github.com/TwoSevenOneT/EDR-Redir) class). **T1.**
- [ ] **F-05** Bind link or Cloud Filter that makes the product open attacker-controlled files under its own path. **T1.**
- [ ] **F-06** Alternate data stream write of a payload next to a trusted name. **T0/T1.**
- [ ] **F-07** `MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)` / `PendingFileRenameOperations` against Program Files or ProgramData. **T1** + reboot.
- [ ] **F-08** Change `ProgramData` or a product env/registry path so protection applies to the wrong tree. **T1** + reboot.
- [ ] **F-09** Dismount / remount / raw volume / partition edit that hides the protected volume. **T1.**
- [ ] **F-10** Safe mode: delete or replace binaries and data. **T1** + reboot. Hold = repair or block on next normal boot.
- [ ] **F-11** Volume Shadow Copy delete / resize / filter bypass. **T1.** Hold = VSS still protected or the attempt is alerted.
- [ ] **F-12** Memory-mapped overwrite of a watched file (no `IRP_MJ_WRITE` the detector expected). **T1.**
- [ ] **F-13** Folder-exclusion or allowlist entry that a T0 user can widen. **T0.**
- [ ] **F-14** Trusted-path / MotW / "signed in a trusted directory" shortcut for an attacker-writable location. **T0/T1.**

## 7. Registry

- [ ] **R-01** Set / delete product policy keys from T1. Hold = callback blocks, ACL is irrelevant.
- [ ] **R-02** Same before first cloud check-in (policy-off window). **T1.**
- [ ] **R-03** `NtLoadKey` / `NtUnLoadKey` / `NtSaveKey` / `RegRestoreKey` on a protected hive. **T1.**
- [ ] **R-04** Service key change (`ImagePath`, FailureActions, required privileges) for the agent or driver. **T1.**
- [ ] **R-05** Unhooked notify classes the product claims to cover — list the ones you actually fired. **T1.**
- [ ] **R-06** Offline hive edit (another OS / PE) then boot back. **T1.**

## 8. Kernel integrity and BYOVD

- [ ] **K-01** Load a Microsoft-blocklisted vulnerable driver with HVCI off. **T1.** Hold = load refused or immediately alerted.
- [ ] **K-02** Repeat with HVCI / Memory Integrity on. **T1.**
- [ ] **K-03** If a lab driver loads: process kill of the agent via kernel handle. **T3.** Hold = product notices and last-gasp / repair fires. Ring-0 write itself is not the bug.
- [ ] **K-04** Callback-table wipe (process / image / registry / object) after a lab driver load. **T3.** Hold = integrity check or unload-watch.
- [ ] **K-05** Minifilter Pre/Post pointer patch or instance detach via kernel write. **T3.**
- [ ] **K-06** Driver unload via SCM, `NtUnloadDriver`, or a third-party killer class. **T1/T3.**
- [ ] **K-07** Product driver accepts a client that fails signature / hash allowlist. **T1.**
- [ ] **K-08** Hash-cache or "already scanned" map poison that later lets a blocklisted image or driver through. **T1.**

## 9. Filter ports and trusted messages

- [ ] **C-01** Connect to the product's filter communication port from a non-product process. **T1.** Hold = connect refused.
- [ ] **C-02** Boot-order race: own service in an early load group, occupy the port or inject before the real client. **T1** + reboot.
- [ ] **C-03** Malformed message / oversized buffer / unexpected type. **T1.** Hold = fail closed, no BSOD, no third-party process kill.
- [ ] **C-04** Well-formed command that should only be valid from the companion (policy off, process kill, exclusion add). **T1.**
- [ ] **C-05** Local RPC / gRPC / named pipe with a secret shipped in the binary. **T0/T1.** Hold = device-bound auth, not a string in `.rdata`.
- [ ] **C-06** Look-alike process name, window, or service that the driver or UX treats as the real UI. **T1.**

## 10. Telemetry and channel

- [ ] **N-01** Host firewall rule isolating the agent image. **T1.** Hold = local enforcement continues; isolation is visible.
- [ ] **N-02** WFP callout / filter that drops the product's destinations. **T1.**
- [ ] **N-03** MITM of the agent-to-cloud channel (broken pin, name-only pin, accepted extra CA). **T1.**
- [ ] **N-04** Spoofed heartbeat or health event from a local peer. **T1.**
- [ ] **N-05** Spoofed alert / last-gasp / "I am fine" after you have isolated or crashed the agent. **T1.**
- [ ] **N-06** Offline mode: ransomware-class writes still detected without cloud. **T1.**
- [ ] **N-07** Cloud-delivered policy field that can panic or disable a sensor (zero TTL, empty rule). **T1** in a lab proxy only.

## 11. Lifecycle: install, uninstall, upgrade, boot

- [ ] **B-01** Official uninstall / maintenance path without the authorized secret. **T1.**
- [ ] **B-02** Forge, replay, or brute a local maintenance token (weak alg, hardcoded key, leftover heap). **T1.**
- [ ] **B-03** `sc stop` / `sc delete` / failure-action wipe. **T1.** Hold = restart-on-fail and registry callback cover the window you actually measured.
- [ ] **B-04** Timing: stop service, replace files, start again before the driver re-protects. **T1.**
- [ ] **B-05** Upgrade / repair installer replace of driver or companion. **T1.**
- [ ] **B-06** Safe mode and WinRE file replace (see F-10). **T1.**
- [ ] **B-07** Early-boot service that talks to the driver before the real agent. **T1** + reboot.
- [ ] **B-08** Signed-config TOCTOU (verify file, then read file again). **T1.**

## 12. Detection logic and parsers

- [ ] **E-01** Entropy / magic / extension write detector: same payload, different write offset, length, and chunking. **T1.** Hold = still alerted.
- [ ] **E-02** Header-only vs body-only vs residual (write, revert, write again) against a content detector. **T1.**
- [ ] **E-03** Rename-into-place after a quiet write in a non-watched extension. **T1.**
- [ ] **E-04** Hash allowlist / blocklist: empty, truncated, colliding, or replayed catalog. **T1.**
- [ ] **E-05** Malformed PE (export table, COM descriptor, cert directory, TLS directory / callbacks). **T0/T1.** Hold = parser fails closed; sensor stays up.
- [ ] **E-06** Malformed Authenticode / DER walk. **T0/T1.**
- [ ] **E-07** Command-line cache / PEB vs real argv mismatch. **T0.**
- [ ] **E-08** Import-resolution / IAT view that disagrees with the on-disk PE. **T1.**
- [ ] **E-09** Malformed ETW or Event Log XML that crashes the consumer. **T0/T1.** Hold = ignore and stay up.
- [ ] **E-10** Forged ETW / Event Log that the driver treats as a trusted command (for example "terminate this image"). **T1.**
- [ ] **E-11** Script / LOLBAS path that drops the same payload the content detector would have caught as a raw write. **T0.**

## 13. Tokens, impersonation, secrets

- [ ] **T-01** Impersonate the agent service token and retry H-01 / C-01 / F-01. **T1.**
- [ ] **T-02** Local interface (gRPC, named pipe, ALPC) accepts a forged or replayed bearer. **T0/T1.**
- [ ] **T-03** Token material not wiped (heap, log, crash dump). **T1.**
- [ ] **T-04** SQLite / state-file keys recoverable from process memory or world-readable files. **T1.**
- [ ] **T-05** Release binary leaks build paths, SBOM, or internal module names that change attacker recon. Hygiene, not a bypass — record separately.

## 14. LOLBAS and living off the land

- [ ] **O-01** Copy / decode / assemble via a signed Microsoft binary ([LOLBAS](https://lolbas-project.github.io/)). **T0.**
- [ ] **O-02** Script host (`wscript`, `mshta`, `powershell` constrained and unconstrained). **T0.**
- [ ] **O-03** `rundll32` / `regsvr32` / `InstallUtil` / `msbuild` class. **T0.**
- [ ] **O-04** Remote or scheduled execution (`schtasks`, WMI, WinRM) of the same payload. **T1.**
- [ ] **O-05** Signed third-party tool that is a known driver or dumper class (lab copies only). **T1.**

## 15. Persistence around the product

- [ ] **X-01** WMI permanent event subscription that fires on agent start/stop. **T1.**
- [ ] **X-02** Scheduled task as SYSTEM that races the anti-tamper loop. **T1.**
- [ ] **X-03** Run / RunOnce / startup folder vs the product's registry and file hooks. **T0/T1.**
- [ ] **X-04** Service in an early load group (see L-05, C-02, B-07). **T1.**
- [ ] **X-05** Firmware / bootkit class — usually a coverage question, not a lab PoC. Record whether the product claims this plane.

## 16. Assessment gate

Do this before a parser or bypass claim. Detail is in [assessment.md](assessment.md).

- [ ] **A-01** Name the real entry point (minifilter, load-image, create-process, registry, filter port, WFP, driver-entry cache). Zero callers = dead code, not a miss.
- [ ] **A-02** List upstream guards. A crash that needs a harness to skip a clamp is a harness artifact.
- [ ] **A-03** Name the feature the parser serves, and the privilege and channel required to deliver input.
- [ ] **A-04** Confirm the feature is on and the agent has received policy. Off-mode tests are inconclusive.
- [ ] **A-05** If the probe was SYSTEM or a parent exemption, repeat it as Session 1 admin before writing "admin can."
- [ ] **A-06** Call-site table exists: site, guard, reachability, delivery, protection. You tested the easiest row first.
- [ ] **A-07** On a parser result, you asked the variant questions: address class, unsigned size, 32-vs-64 sibling, and where a *successful* read goes.
- [ ] **A-08** Other callers and other file locations were checked before concluding anti-tamper blocks the bug.
- [ ] **A-09** SEH scope was checked (outer function vs deferred callback / work item / DPC).
- [ ] **A-10** Allocation size and loop bound come from the same field, or you filed the mismatch.
- [ ] **A-11** A second read after a check (mapped view, registry, shared buffer) was considered for TOCTOU.
- [ ] **A-12** Bugcheck evidence is a full dump: code, faulting instruction, product driver frames.

## 17. Classes the first pass under-weights

- [ ] **G-01** Freeze / suspend / WER dump path leaves the agent process "running" but not scanning. **T1.** Hold = kernel policy still enforces, or a watchdog alerts on stuck threads.
- [ ] **G-02** Altitude collision prevents the minifilter instance from attaching. **T1.** Separate from T3 detach.
- [ ] **G-03** Application-control policy (WDAC / AppLocker) denies the sensor's own binaries. **T1.**
- [ ] **G-04** Product allowlist includes an attacker-writable path or a signer you can obtain. **T0/T1.**
- [ ] **G-05** Sparse, compressed, or reparse-point file reaches a size or mapping check the normal file does not. **T1.**
- [ ] **G-06** Alternate data stream or first-open fills a per-file hash cache; the default stream is then replaced. **T1.**
- [ ] **G-07** On-disk cache or service-parameter blob parsed at driver start is not produced by the agent. **T1** + reboot. Hold = rejected, no boot loop.
- [ ] **G-08** Local policy database edited without a cloud signature. **T1.** Hold = ignored or overwritten and logged.
- [ ] **G-09** Decoy service or window whose name matches a last-gasp / peer-product heuristic. **T1.**
- [ ] **G-10** Signature check is presence or a subject string, not chain plus hash. **T1.**
- [ ] **G-11** 32-bit and 64-bit parser siblings do not share the same bounds check. **T0/T1.**
- [ ] **G-12** Callback or dispatch integrity after a lab driver load (T3 only). Hold = alert or repair, not "kernel write is impossible."

## 18. Evidence close-out

- [ ] **Z-01** Every miss has a product oracle (log, block, absence of restart), not only a custom probe.
- [ ] **Z-02** Every miss names the privilege and the single variable you changed.
- [ ] **Z-03** Holds are recorded too. A campaign of only misses is a sampling bias.
- [ ] **Z-04** Crashes are filed as availability of protection, with dump / bugcheck code.
- [ ] **Z-05** Nothing in the writeup names a customer, a private ticket, or a non-public IOCTL.

## Suggested order for a first pass

1. S-01 … S-05 (oracle alive)
2. U-01, F-01, H-01, N-01 (four planes, one hour)
3. P-02, P-03, D-01, F-04, F-07 (public, high-churn classes)
4. C-01, C-02, B-01, K-01 (trust and lifecycle)
5. E-01, E-05, E-09 (parsers and detectors)
6. A-01 … A-07 on any parser claim, then G-01, G-06, G-07
7. Close with Z-01 … Z-05
