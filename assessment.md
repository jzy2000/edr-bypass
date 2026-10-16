# Assessment discipline

How to decide what to test, and when a result is a miss, a hold, or inconclusive. This is the loop used by a careful product-security PoC, written as public method. It does not name a product, a ticket, or a payload.

Read [methodology.md](methodology.md) for privilege tiers and evidence. Use this file before you invent a second delivery path.

## Gate, before any probe

Answer these in order. If one fails, stop and record why.

1. **Reachability.** From the function you care about, walk callers until you hit a real entry: minifilter callback, load-image or create-process notify, registry callback, filter-port dispatch, WFP callout, or driver entry that loads a cache. Zero callers means dead code. Dead code is not a bypass.
2. **Upstream guards.** List every check between attacker-controlled input and that function: type and length checks, SEH, "is this PE mappable," policy mode, image-hash allowlist. A crash that only exists because a harness skipped a clamp is a harness artifact.
3. **Feature the parser serves.** File resilience, network awareness, injection, vulnerable-driver detection, command-line policy, certificate trust. The feature tells you *when* the code runs and *what shape* of input reaches it.
4. **Who can deliver the input.** Privilege, process, and channel. If the only path is an intact control (anti-tamper on the product's own files, a signed cloud policy, a single trusted client on a port), say the finding is out of scope unless you have already shown that control fails. Do not assume the control is broken.

## Feature and token checks

A quiet product is not a miss until you know the sensor was on and the token was not exempt.

- Agent connected, and the policy you think you are testing is actually loaded. Many drivers start in an off or detect-only mode until the first cloud config arrives.
- The specific feature is active. An injected user-mode sensor that is not loaded in any process means injection is off. Tests in that window are inconclusive.
- Anti-tamper is not in its post-boot "policy not yet pushed" window.
- The probe is not SYSTEM / Session 0 unless you are deliberately testing the SYSTEM exemption. Remoting that runs as SYSTEM is exempt from many "own process or system" gates. Repeat the same action as a Session 1 admin before you claim "admin is enough."
- Record the observed state next to the result: sensor loaded or not, policy mode, token, session.

## Rank call sites, then build

Before writing a probe, make a table. One row per caller of the weak function.

| Site | Guard present | What must be true to reach it | How input arrives | Protections on that input |
|---|---|---|---|---|
| … | SEH, bounds, policy, none | hash match, timing, privilege | file, DLL, registry, IOCTL, network | anti-tamper, WRP, ACL |

Pick the row with the fewest gates. If that path fails twice for the same reason, take the next row. Do not keep inventing variants of a blocked path.

When a direct write is blocked, the usual indirect classes are already on the checklist: bind link, pending rename, junction, search-order hijack, parent-directory redirect. Test those as classes. Do not treat one file's gap as the whole list: if a rename is allowed on one protected path, walk the rest of the protect list.

## Trigger classes

Try the class that matches the entry point. Do not stop at the first one that is merely convenient.

| Class | Input the product parses | Typical entry |
|---|---|---|
| Crafted image | PE headers, export/import, cert directory, TLS directory, section counts | Load-image notify, create-process, post-create hash |
| On-disk cache | Packed or encrypted blob the driver reads at start | Driver entry, service parameters |
| Trusted IPC | Filter-port or device messages from the "official" client | Communication callback |
| Policy store | Local database or signed config the agent reloads | Agent start, cloud poll |
| Service config | Values under the driver's service key | Driver or agent init |
| Network metadata | Flow context a WFP callout trusts | Connect, accept, datagram |
| Companion image | The injected sensor DLL the driver parses during injection | Process create |
| Odd files | Sparse, compressed, reparse, alternate streams, mapped views | Filesystem callback |
| Image tricks | Ghosting, herpaderping, hollowing, deleted backing file | Create-process notify |

A short-lived process can exit before an async injection or scan finishes. If the oracle is "injection did not run," confirm the process was still alive, not that the parser is safe.

## Variant questions

After the first result, ask these before you close the item. They are questions, not procedures. A "yes" means file a separate claim with its own oracle.

1. **Address class.** A user pointer that faults may be caught by SEH. A pointer that does *not* fault may be read for real. Where does that data land, and can a user see it?
2. **Unsigned size math.** A short length subtracted from a larger bound, or added to a base, can wrap. Does the parser have that pattern on a field you control?
3. **32-bit vs 64-bit sibling.** One width has a range check. Does the other?
4. **Other callers.** A guarded caller was tested. Is there an unguarded caller of the same function?
5. **Other locations.** Install-dir anti-tamper blocked the file. Does load-image, a non-protected directory, or the companion DLL still reach the parser?
6. **Data flow after a successful read.** Fault is denial of service. A successful read that is copied into a user-visible buffer is disclosure. A value used as a size or function pointer is a different class. Name the class from where the data goes.
7. **Signedness.** A size compared as signed can pass when the high bit is set. Check comparisons on sizes, offsets, and counts.
8. **Allocation vs use.** The buffer size comes from one field and the loop bound from another. Are they the same field?
9. **TOCTOU.** Validated on a mapped view or registry value, then used from a second read. Can the producer change the value in between?
10. **SEH scope.** The `__try` wraps the outer function. Does the weak read run in a callback, work item, or DPC outside that scope?
11. **Race.** Two processors, or a burst of events, so the second read differs from the first.
12. **Chain.** A one-byte over-read alone is small. Does it leak a pointer the next bug can use? Record the chain only if both ends are demonstrated.
13. **Forged events.** The consumer trusts an ETW provider, event log, named pipe, or shared channel. Can a local user emit the same shape without being the real producer?
14. **Handle mask.** List every process and thread right that can kill, inject, dump, or impersonate. One leftover right is enough. "Terminate is stripped" is not coverage.
15. **Search order.** A protected process loads a DLL that is missing or registered from an unprotected key (COM, performance counter). Does that load inherit the process's trust?
16. **First client.** A port allows one connection and checks the image of whoever connects first. Can an earlier service take that slot?
17. **Signature shortcut.** Presence of a signature, a subject string, or a file name, instead of a chain and a hash. Say which check you actually observed.
18. **Path source vs path destination.** Anti-tamper covers the resolved path. The registry value, environment variable, mount, or bind link that *chooses* the path may be uncovered.
19. **Inspection window.** Content checks key off offset, length, or extension at the moment of the write. Split writes and rename-around are different tests.
20. **Cached file context.** A hash or verdict stored on the file object can be filled from a benign stream or an earlier clean open, then the default stream changes.

Check at least address class, unsigned size, the 32/64 sibling, and "what if the read succeeds" on any parser bug before you call it denial-of-service only.

## What "fail" is allowed to mean

- **Blocked.** Name the gate: policy off, anti-tamper, missing feature, HVCI, SEH caught it, wrong token.
- **Inconclusive.** Oracle was down, feature was off, or you only tested an exempt token.
- **Miss.** The outcome happened and the product's own log, block, or continued enforcement did not.

Do not upgrade a caught fault into code execution. Do not downgrade a successful read into a crash because a different pointer would have faulted.

## Evidence

Full memory dump when the box bugchecks. Bugcheck code, faulting instruction, and the product driver frames. A minidump is not the record.

State what user-mode APIs can already see. Data that `NtQuerySystemInformation` or a documented API returns is not a kernel disclosure.
