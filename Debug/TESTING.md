# Regression testing

## Setup

The application itself needs no third-party PowerShell modules. To run the complete test suite, open Windows PowerShell 5.1 and install the same dependencies pinned in CI from the PowerShell Gallery:

```powershell
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force
Install-Module Pester -RequiredVersion 4.10.1 -Scope CurrentUser -Force -AllowClobber -SkipPublisherCheck
Install-Module PSScriptAnalyzer -RequiredVersion 1.25.0 -Scope CurrentUser -Force
```

These commands install modules for the current user. The tests do not require administrator elevation. The runner supports Pester 3.4 and 4.x and selects the highest compatible installed version; Pester 5 alone will not satisfy the dependency.

The pinned Pester install uses `-SkipPublisherCheck` to allow its older signing certificate chain alongside preinstalled Pester 5. This bypasses PowerShellGet's comparison with the installed module's publisher certificate.

## Run

Run from the repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Debug\test_regression.ps1
```

The runner uses Windows PowerShell 5.1, Pester 3.4 or 4.x, and PSScriptAnalyzer. CI installs pinned Pester 4.10.1 and PSScriptAnalyzer 1.25.0. Each suite runs in a separate process, with a five-minute timeout and a nonzero exit status on failure. Missing dependencies, missing suites, empty Pester suites, skipped or pending tests, crashes, and timeouts fail the run. The runner continues collecting results after individual failures.

## Coverage

The suite includes existing privacy, updater, network math, export, profiles, and log-query regressions, plus named Pester cases for:

- Static, DHCP, APIPA, empty, asymmetric address stores, multiple addresses, and stale persistent routes.
- Address, gateway, DNS, and final verification failures in each starting state, with rollback comparisons.
- Repeated applies, operation ordering, transient retries, gateway-free profiles, incomplete recovery, snapshot failure, conflict cancellation, and WhatIf.
- Durable route creation with the documented dual-store default, active-route collisions, asymmetric route stores, differing recovery metrics, and visible gateway provider errors. The route mock rejects explicit PersistentStore creation.
- Input validation, subnet arithmetic, narrow subnets, prompt cancellation, corrupt profiles, file retention, unique backups, consent types, MAC cache, DNS and traceroute boundaries, TCP resource cleanup, update rejection, and console guards.
- Runner crash, missing-suite, empty-suite, timeout, and successful-suite reporting.

Networking and external-service boundaries are mocked. Tests do not change real adapter settings. Filesystem cases use isolated fixtures beneath the ignored `Debug/test-results` directory.

Results include `summary.json`, per-suite logs, Pester JSON and JUnit XML. Pester command coverage uses a generated function-only copy of the application, preserving original line numbers. Startup and the interactive menu loop are excluded from execution. Coverage counts describe commands exercised by those Pester suites; they are not a claim of complete behavioral coverage. Standalone regressions exercise additional code without contributing to those counts.

## Release validation

### Observed results

As of 2026-10-06, the latest local Windows PowerShell 5.1 run passed all 11 suites: 62 core Pester cases, 68 transaction Pester cases, seven standalone regression suites, static checks, and runner self-tests. Local Pester was 3.4.0. [GitHub CI with Pester 4.10.1](https://github.com/Dantdmnl/Network_Configuration_Script/actions/runs/37493290959) also passed all 11 suites and 130 named tests, along with PSScriptAnalyzer, workflow analysis, and CodeQL checks.

User-provided Proxmox Windows VM transcripts confirm:

- Profile static reapplication and manual static reapplication with changed DNS.
- Static-to-DHCP conversion, obtaining `192.168.1.59`.
- DHCP-to-static profile application, obtaining `192.168.1.25/24`, gateway `192.168.1.1`, DNS `1.1.1.1, 9.9.9.9`, and DHCP disabled, with final verification passing.
- Successful recovery reported after a failed gateway apply. The transcript does not independently verify the restored state.

Windows build, NIC model, and driver version were not supplied. These observations confirm the reported workflows on that guest; they do not complete the entire checklist below.

### Live validation checklist

Automation cannot cover every Windows driver, timing race, DHCP server, or hypervisor. Use a disposable Windows guest with a VM snapshot and console access. Record Windows build, PowerShell version, NIC model, and driver version; test VirtIO and an emulated NIC where available.

Status reflects user-provided guest transcripts as of 2026-10-06. **Confirmed** means the listed workflow succeeded on that guest; **Partial** means some observations or variants remain unverified; **Pending** means no live evidence has been recorded.

| Check | Status | Evidence or remaining work |
| --- | --- | --- |
| Profile and manual static reapplication | Confirmed | Both succeeded; manual reapplication changed DNS. |
| Changed address and same-address prefix changes | Pending | Exercise both changes and inspect resulting stores. |
| Static-to-DHCP and DHCP-to-static | Confirmed | DHCP acquired `.59`; the static profile restored `.25/24`, gateway, DNS order, and disabled DHCP. |
| Lease origin and address readiness | Partial | Application verification passed; capture raw provider state independently. |
| Multiple adapters with default routes | Pending | Verify the other adapter's addresses, routes, metrics, and DNS remain unchanged. |
| Stale persistent routes and gateway-free profiles | Pending | Verify obsolete defaults disappear and custom routes remain. |
| Reboot persistence | Pending | Inspect address, route, and DNS state after reboot. |
| Recovery after gateway failure | Partial | Successful recovery banner observed; verify exact restored state. |
| Failed DHCP renewal and manual DNS recovery | Pending | Exercise failed renewal and static-apply recovery with a manual DNS override. |
| Duplicate addresses, reconnects, and slow DAD | Pending | Verify failure/recovery and absence of false success banners. |
| IPv6 DNS preservation | Pending | Compare before/after static apply, DHCP conversion, and recovery. |

Record before/after address, route, DHCP, and DNS state, including ActiveStore and PersistentStore. Version 3.0 is published with the pending checks above documented as limits of live validation; complete them to broaden hardware and recovery coverage.
