# Public references

Canonical writeups for technique classes named in this repo. Prefer the original paper or vendor doc over a recap blog.

## Process creation and image tricks

- [Process Ghosting](https://www.elastic.co/blog/process-ghosting-a-new-executable-image-tampering-attack) — Gabriel Landau / Elastic
- [Process Herpaderping](https://jxy-s.github.io/herpaderping/) — Johnny Shaw
- [Process Doppelgänging](https://www.blackhat.com/docs/eu-17/materials/eu-17-Liberman-Lost-In-Transaction-Process-Doppelganging.pdf) — enSilo / Black Hat EU 2017
- [Process Hollowing](https://attack.mitre.org/techniques/T1055/012/) — MITRE ATT&CK T1055.012
- [Catching attacks that evade detection with process creation properties](https://www.microsoft.com/en-us/security/blog/2022/06/30/using-process-creation-properties-to-catch-evasion-techniques/) — Microsoft

## Userland hooks, syscalls, AMSI, ETW

- [Direct system calls and Hell's Gate](https://github.com/am0nsec/HellsGate)
- [SysWhispers3](https://github.com/klezVirus/SysWhispers3)
- [Tampering with Windows Event Tracing](https://blog.f-secure.com/silencing-etw-and-amsi/) — public ETW/AMSI silence patterns
- [Antimalware Scan Interface](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal) — Microsoft

## Self-protect, PPL, ELAM

- [Protected Processes Light](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-) — Microsoft
- [ObRegisterCallbacks](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks) — Microsoft
- [ELAM](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/elam-driver-requirements) — Microsoft
- [ProcessDestroy BOF](https://github.com/trustedsec/CS-Remote-OPs-BOF) — TrustedSec (handle close / process destroy class)

## Filesystem, minifilter, bind links

- [Filter Manager concepts](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/filter-manager-concepts) — Microsoft
- [Bind links](https://learn.microsoft.com/en-us/windows/win32/cfapi/build-a-cloud-file-sync-engine) and [Windows bindflt](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcreatebindlink)
- [EDR-Redir](https://github.com/TwoSevenOneT/EDR-Redir) — bind-link / folder-redirection research
- [PendingFileRenameOperations](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw) — boot-time replace / delete

## Registry callbacks

- [CmRegisterCallbackEx](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-cmregistercallbackex) — Microsoft
- [Registry notify classes](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_reg_notify_class) — what a callback can actually see

## BYOVD and kernel integrity

- [Microsoft recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules)
- [CISA: increasing use of vulnerable drivers](https://www.cisa.gov/news-events/cybersecurity-advisories)
- [Kernel Driver Utility](https://github.com/hfiref0x/KDU) — research loader (lab only)
- [EDRSandblast](https://github.com/wavestone-cdt/EDRSandblast) — callback / ETW / unhook research

## Network isolation

- [Windows Filtering Platform](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page) — Microsoft
- [Windows Firewall with Advanced Security](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/)

## LOLBAS and living off the land

- [LOLBAS project](https://lolbas-project.github.io/)
- [MITRE ATT&CK: Impair Defenses](https://attack.mitre.org/tactics/TA0005/)

## MITRE technique IDs used as labels (not a complete map)

| Class | ATT&CK |
|---|---|
| Indirect / direct syscalls | T1106 |
| Process injection | T1055 |
| Process hollowing | T1055.012 |
| DLL search-order hijack | T1574.001 |
| Sideloading | T1574.002 |
| COM hijack | T1546.015 |
| Impair defenses | T1562 |
| Indicator blocking (ETW/AMSI) | T1562.006 |
| Hidden files / NTFS tricks | T1564 |
| Boot / safe mode | T1562.009 |
| Valid accounts / token | T1134 |
| Ingress tool transfer / copy | T1105 |
