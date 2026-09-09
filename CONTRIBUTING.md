# Contributing

This repo is a **public testing checklist**. Keep it that way.

## Accept

- New technique *classes* that are already discussed in public research
- Clearer oracles (what "hold" vs "miss" looks like)
- Coverage gaps in the control-plane matrix
- Public references (papers, talks, Microsoft docs, well-known research tools)
- Clarifications to [methodology.md](methodology.md)

## Reject

- Vendor, product, team, or employee names
- Internal ticket IDs, wiki links, hostnames, customer data
- Unpublished vulnerability details or vendor-specific IOCTL / device / port names
- Exploit source, shellcode, vulnerable-driver payloads, or "run this to kill X"
- Step-by-step attack procedures that a reader can follow to compromise a live product
- Cloud / SaaS / CI findings that are not endpoint EDR evasion

If a note only makes sense because you tested one commercial agent last week, generalize it until the vendor disappears. If it cannot be generalized, it does not belong here.

## Style

- One checkbox = one testable claim
- Privilege assumed, then the oracle, then what to record
- Link the first mention of a named public technique to a canonical writeup
- No backticks inside markdown link text: write [NtCopyFile](nt-copyfile.cpp), not a code-span link
- No emoji
