# Technique notes

Short context for each class in [CHECKLIST.md](CHECKLIST.md). No reproduction procedures. If a paragraph starts to look like a recipe, it belongs in a private tracker, not here.

## 1. Userland hooks vs native API

Many products hook `KernelBase` / `kernel32` exports (`CopyFileExW`, `CreateProcessW`, `WriteFile`). The same work through `ntdll` (`NtCreateFile`, `NtWriteFile`, `NtCreateUserProcess`) is a different surface. [nt-copyfile.cpp](nt-copyfile.cpp) is the repo's only code sample: it copies a file with `NtCreateFile` / `NtReadFile` / `NtWriteFile` so you can compare the product's reaction to a `CopyFileExW` baseline.

**Oracle.** Same bytes land on disk. Hold = the product still logs or blocks the write. Miss = only the Win32 path is visible.

Also exercise `\??\` and `\\?\` paths, `NtSetInformationFile` renames, and memory-mapped views (`CreateFileMapping` + `MapViewOfFile`). Mapped writes often skip `IRP_MJ_WRITE` shapes that a content detector keyed on.

## 2. Syscalls, unhooking, AMSI, ETW

[Hell's Gate](https://github.com/am0nsec/HellsGate) and [SysWhispers](https://github.com/klezVirus/SysWhispers3) popularized reading syscall numbers from a clean `ntdll` and issuing `syscall` without passing through a hooked stub. Related classes: restore a clean `.text` from a disk copy, patch AMSI (`AmsiScanBuffer`), patch or unregister ETW (`EtwEventWrite`, Threat-Intelligence sessions).

**Oracle.** A script or in-memory loader that the product catches via AMSI/ETW still gets caught after the patch *or* a downstream sensor (minifilter, kernel ETW, memory scan) still fires. Miss = userland-only sensors go dark and nothing else picks it up.

## 3. Process creation evasion

Windows image-load callbacks generally fire when the first thread starts, not when the process object is created. Public classes that abuse the gap:

- [Ghosting](https://www.elastic.co/blog/process-ghosting-a-new-executable-image-tampering-attack) — delete-pending file, section still valid
- [Herpaderping](https://jxy-s.github.io/herpaderping/) — section cached, on-disk bytes replaced
- [Doppelgänging](https://www.blackhat.com/docs/eu-17/materials/eu-17-Liberman-Lost-In-Transaction-Process-Doppelganging.pdf) — TxF, file never committed (limited on modern builds)
- [Hollowing](https://attack.mitre.org/techniques/T1055/012/) — suspended legitimate process, image replaced

**Oracle.** [Microsoft's process-creation properties](https://www.microsoft.com/en-us/security/blog/2022/06/30/using-process-creation-properties-to-catch-evasion-techniques/) writeup is the right detection mindset: section vs file hash, `DeletePending`, `FileOpenNameAvailable`. Hold = create is blocked or alerted. Miss = a child runs with no image the scanner can open.

## 4. Injection and stomping

Classic remote-thread injection, APC, mapping a section into a peer, reflective load, and module stomping (map a signed DLL, overwrite its RX). Also: inject into a *trusted sibling* (tray UI, updater, crash helper) that the driver treats as "own process."

**Oracle.** Target process still protected; injected module either never runs or is alerted; sibling processes are not a free pass into the driver's allowlist.

## 5. DLL and COM hijack

[Search-order hijack](https://attack.mitre.org/techniques/T1574/001/) and [sideload](https://attack.mitre.org/techniques/T1574/002/) of a missing or attacker-writable import next to a privileged binary. COM hijack (`InprocServer32` under HKCU). Phantom DLLs. Performance-counter `Library` values. `AppInit_DLLs` / `AppCertDlls` if those keys are unprotected.

**Oracle.** The privileged image does not load attacker code; the product blocks the write or the load; hijack of a *sibling* binary does not inherit the agent's allowlist.

## 6. Self-protect: handles and rights

`ObRegisterCallbacks` can strip rights on `OpenProcess` / `OpenThread` / duplicate. Public gaps testers keep seeing:

- Rights left on the mask (`PROCESS_CREATE_THREAD`, `PROCESS_SET_INFORMATION`, `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, quota / job)
- Parent-process exemption: `CreateProcess` on the agent path yields a full handle
- Duplicate-close (`DUPLICATE_CLOSE_SOURCE`) tearing down the agent's handles
- Thread mask weaker than the process mask

**Oracle.** After `OpenProcess(PROCESS_ALL_ACCESS)` from a non-exempt token, inspect `GrantedAccess`. Hold = invasive bits gone *and* the leftover bits cannot kill, dump, or run code in the process. Miss = a leftover right is enough to crash, dump secrets, or create a thread. "Handle opened" alone is not a miss.

Memory scraping of an unprotected user-mode agent is a confidentiality test, not a brag. Record whether secrets are encrypted at rest in the process and whether the dump was possible only after an Ob-callback miss.

## 7. PPL, ELAM, and "not PPL"

[PPL](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-) and [ELAM](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/elam-driver-requirements) are Microsoft programs with signer levels (`PsProtectedSignerAntimalware`, …). Many products are intentionally *not* PPL and compensate with object callbacks.

**Oracle.** "Not PPL" is a design note. A finding needs a chain: leftover right *or* trusted-sibling hijack *or* kernel write that makes the compensation fail. Also test whether the product validates the *signature of its own user-mode companion* before talking to it.

## 8. Minifilter and filesystem restrictions

Write / rename / delete guards on install and data directories. Common miss classes:

- Altitude: unload or attach below / above the product so IRPs never arrive
- Reparse points, bind links, directory junctions, `\??\` aliases
- Alternate data streams
- Boot-time `PendingFileRenameOperations` / `MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)`
- Environment or `ProgramData` redirection so the product protects the wrong tree
- Volume / partition tricks (dismount, mount over, raw volume write)
- Safe mode, where filters and services often do not start

**Oracle.** The bytes the product cares about cannot be changed or relocated by a non-exempt token, including after reboot and in safe mode. A successful write that the product later repairs still needs a log line; silent repair-only is a detection miss even if integrity holds.

## 9. Bind link and folder redirection

[EDR-Redir](https://github.com/TwoSevenOneT/EDR-Redir) showed that bind links / Cloud Filter on a *parent* of a protected directory can make the product's own path resolve into attacker-controlled space. That is a namespace problem, not a "can I write Program Files" problem.

**Oracle.** Creating bind links on `Program Files`, `ProgramData`, or the product prefix is blocked or alerted; after a link exists, the product still opens the real files.

## 10. Registry callbacks

[CmRegisterCallbackEx](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-cmregistercallbackex) sees a specific [notify class](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_reg_notify_class) set. Testers check whether `LoadKey` / `UnLoadKey` / `SaveKey` / `RestoreKey` / replace are hooked, whether service keys are in the protect list only after cloud policy arrives, and whether `NtLoadKey` of a cloned hive is a back door.

**Oracle.** Policy and service keys cannot be changed from a non-exempt token in any notify class the product claims to cover. "Protect" that is off until first cloud check-in is an early-boot window.

## 11. BYOVD and kernel integrity

Bring-Your-Own-Vulnerable-Driver is the dominant real-world EDR-killer class ([CISA](https://www.cisa.gov/news-events/cybersecurity-advisories), [Microsoft block list](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules)). Once a signed-but-vulnerable driver is in, attackers use it to kill processes, unhook callbacks, or unload the product.

**Oracle.** Known-vulnerable hashes do not load (HVCI / blocklist / own allowlist). If a lab driver *does* load, the product still notices callback table damage, unexpected unloads, and process kills of its own image. Ring-0 arbitrary write is not a product bug; failing to constrain *which* drivers can get there is.

Also test: does the product's own driver refuse to talk to an unsigned or swapped user-mode client? Does a cert check compare subject name instead of chain + hash?

## 12. Kernel callbacks and filter communication

Besides Ob / Cm / image notify, products expose filter communication ports so user-mode can send commands. Those ports need an allowlist (image path hash, single connection, message schema). Public miss classes: impersonate the agent at boot (start earlier, inject, connect first), send a malformed message that crashes the driver, or send a well-formed message that terminates someone else.

**Oracle.** Only the genuine, running, signed companion can connect. Malformed messages fail closed (no BSOD, no third-party kill). A crash is a finding even when you cannot turn it into code execution.

## 13. Telemetry, WFP, and last gasp

[WFP](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page) and host firewall rules can isolate the sensor from its cloud. Related: MITM of a weakly pinned channel, spoofed heartbeats, spoofed alerts, and "last gasp" events that are supposed to fire when the agent is dying.

**Oracle.** Isolation is visible (local cache, last-gasp, watchdog). Channel authenticity is not "TLS to a name" only (pinning, device identity). Heartbeats and alerts cannot be injected by a local peer. Offline detection still does something useful.

## 14. Lifecycle: uninstall, upgrade, maintenance, boot

Local maintenance / uninstall codes, timing races around service stop vs driver unload, upgrade file replace, and safe-mode deletion. CPU priority / freeze of the agent process is a cheap availability attack against user-mode sensors.

**Oracle.** Uninstall and maintenance require a secret the local admin cannot mint. Stop / delete / upgrade either stays protected or comes back before the attacker finishes. Safe mode does not leave data and binaries world-writable with no repair.

## 15. Detection logic and parsers

Content detectors (entropy, header magic, extension, hash) that key on write offset and length can be shaped around. Hash caches and "already scanned" maps can be poisoned. Folder exclusions and trusted-path / MotW shortcuts are policy, not bugs, until they apply to attacker-writable locations.

Untrusted parsers (PE export / COM / cert directory / TLS, Authenticode, cmdline cache, DER) must fail closed. A malformed PE that skips a user-mode sensor, or a malformed ETW event that crashes the consumer, is a robustness finding.

**Oracle.** Shaped writes that still encrypt or drop a payload are still detected. Malformed input does not disable a sensor and does not panic the agent. Exclusions cannot be widened from T0.

## 16. Tokens, impersonation, named objects

Token steal / impersonate of the agent service, named-pipe or ALPC peer spoof, local gRPC / RPC with a baked-in shared secret, and UI-helper impersonation.

**Oracle.** Local interfaces authenticate a device-bound secret, not a string in the binary. Named objects used for command and control are ACL'd and verified. A look-alike process name or window does not receive driver trust.

## 17. LOLBAS

[LOLBAS](https://lolbas-project.github.io/) copies, decodes, compiles, or proxies without a new malware family. Script hosts, `rundll32`, `regsvr32`, `mshta`, `InstallUtil`, signed-driver utilities, and living-off-the-land compressors.

**Oracle.** The product's file and process sensors still see the *effect* (payload on disk, child with odd parent, network). A signed Microsoft binary is not a free pass.

## 18. Persistence that outlives the agent

WMI event subscriptions, scheduled tasks, COM / Run keys, services in the Filter load group, UEFI / bootkit (out of reach for most endpoint tests, still a coverage question).

**Oracle.** Persistence that fires around the product's start is logged. Early-boot services cannot occupy the product's communication slot.

## 19. Freeze and coma

Killing the agent trips a watchdog. Suspending it often does not: the process still looks alive. Public classes include working-set starvation, thread suspend, job freeze, and Windows Error Reporting dump paths that suspend every thread of a target and then fail to resume them. [WerFaultSecure](https://learn.microsoft.com/en-us/windows/win32/wer/windows-error-reporting) runs as a protected process, which is why a dump of a protected image is a different privilege story than `OpenProcess` from an ordinary admin.

**Oracle.** After the freeze, kernel enforcement (minifilter, object callbacks, WFP) still holds, or a watchdog notices threads that are not running. Miss = user-mode sensors stop and nothing restarts or alerts because the process object never exited.

## 20. Minifilter altitude and detach

Filter Manager orders minifilters by altitude. A colliding altitude can keep the product's instance from attaching. With kernel write, detaching an instance or swapping pre/post callbacks blinds file telemetry without unloading the driver service. That is a T3 integrity test. User-mode altitude tamper is a T1 registry test (see the registry section) and is a different claim.

**Oracle.** `fltmc` still shows the instance at the expected altitude after the attempt, and a canary write is still blocked or logged. Miss = the instance is gone or shadowed and file policy goes quiet.

## 21. WDAC and AppLocker as a weapon

Application control can deny the product's own binaries, DLLs, and drivers if an admin can deploy a policy. That is "Windows blocking the sensor," not a parser bug. Also test the reverse: the product's allowlist trusts a path or signer the tester can write.

**Oracle.** A new code-integrity policy that targets the sensor is blocked, or the product repairs on next boot and alerts. An attacker-writable directory is not on the product's trust list.

## 22. Callback and dispatch integrity

Products register process, thread, image, registry, and object callbacks, and they handle IRPs. With a lab driver loaded, the question is whether the product notices a missing callback or a swapped dispatch routine. Ring-0 write is assumed at T3. The finding is the lack of an integrity or last-gasp signal, not the fact that kernel code can write kernel memory.

**Oracle.** Callback removal or a silent unload produces an alert or a repair. Direct kernel object edits that hide a process are the same class: the sensor's view and the scheduler's view diverge, and something should say so.

## 23. Parser robustness

Image, certificate, command-line, and cache parsers fail in more than one way. Map the failure to a class:

| What you changed | If the product dies | If it returns bad data | If it skips the scan |
|---|---|---|---|
| Header field, count, RVA | Availability | Disclosure or wrong trust | Detection bypass |
| 32-bit path vs 64-bit path | Same bug, second site | | |
| Size that wraps | Pool corruption | | |
| Pointer that faults vs pointer that is valid | Crash vs silent read | | |
| Cache blob at driver entry | Boot loop | | |

SEH around the outer function does not cover a deferred callback. Say which scope you checked.

**Oracle.** Malformed input is dropped, the sensor stays up, and a later well-formed bad file is still caught. Miss = the process or driver dies, or this one file is exempt forever.

## 24. Policy store and config cache

Two stores show up on almost every agent: a local policy database the user-mode service reloads, and a cache the driver reads from its service key at start. Both are "the product trusts bytes it wrote earlier."

**Oracle.** A local edit without the cloud signature does not stick, or it is overwritten on the next poll and logged. A cache blob that is not produced by the agent does not parse into a policy change, an exclusion, or a crash-on-boot. Cutting the network to freeze a lab policy is a test harness issue: record that you isolated the agent, and restore it.

## 25. Own-process and parent exemptions

Callbacks often allow the product's own image, its parent, and SYSTEM. That is required for the agent to manage itself. It becomes a bypass only when an outsider can *become* that image or that parent: hollow the UI helper, plant a DLL the helper loads, or `CreateProcess` the agent suspended and keep the parent's handle.

**Oracle.** A non-product parent does not receive a full handle. Code running inside a sibling does not inherit filter-port or file-protect exemptions unless that sibling is supposed to be trusted, and you have said so.

## 26. Decoy identity

Some "last gasp" or multi-product logic keys off service name, image name, or a window class. A second service that matches the pattern can confuse the heuristic without touching the real agent.

**Oracle.** A look-alike name does not suppress alerts, heartbeats, or tamper response for the real process.
