# Security policy

This repository holds automation that keeps
[alanta/azure-egress-proxy](https://github.com/alanta/azure-egress-proxy) up to date. It
reads that repository and, in later stages, proposes changes to it through pull requests.
A weakness here could become a supply-chain problem there, so reports are welcome.

## Reporting a vulnerability

Please use [private vulnerability reporting](https://github.com/alanta/azure-egress-proxy-sdlc/security/advisories/new)
rather than a public issue. Include what you found, how to reproduce it, and what an
attacker could achieve.

For a vulnerability in the proxy itself, report it to
[azure-egress-proxy](https://github.com/alanta/azure-egress-proxy/security) instead.

## What is in scope

- Workflows and scripts in this repository, and the credentials they use.
- Anything that could let untrusted input (upstream release notes, pull request content,
  registry data) change what this automation proposes, approves or merges.
- Committed fixtures or reports that disclose information that should not be public.
