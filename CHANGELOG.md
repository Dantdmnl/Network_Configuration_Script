# Changelog

All notable changes to this project are documented in this file.

This project follows a practical changelog format for a single-file Windows PowerShell admin utility.

## [3.0] - Unreleased

### Fixed

- Prevent duplicate-gateway failures by configuring IPv4 addresses and default routes separately, reconciling both route stores on the selected adapter, and using the supported dual-store creation default. Gateway-free profiles remove both default-route stores; provider errors appear in the console.
- Handle empty CIM address stores when disabling DHCP removes a lease. Re-read state before retrying partial address creation, preserve a different working address until its replacement is ready, and reject Duplicate or timed-out Tentative addresses.
- Require a readable snapshot before mutation and attempt recovery of previous static or DHCP settings. Restore address stores/prefixes, route stores/metrics, and DNS mode, including manual DHCP DNS overrides; wait for lease readiness and report incomplete recovery.
- Fail configuration when gateway, DNS, or final-state verification fails. Scope DNS changes to IPv4 and verify the requested server order.
- Clear static default routes during DHCP conversion and renew through an adapter-specific CIM method with identity checks, operation timeout, structured result checks, and Preferred DHCP-origin lease verification. Keep formatted failure output out of the returned success value.
- Prevent log rotation or write failures from interrupting configuration and recovery. Reject non-Boolean stored logging consent, including the JSON string `"false"`.
- Include virtual NICs in adapter selection and return when the inventory is empty.

### Changed

- Replace the previous NetBIOS/ARP/TCP conflict-probing sequence with bounded local ownership and selected-interface neighbor checks, followed by Windows address-readiness verification. Negative probes do not prove that an address is unused.
- Refresh documentation for the current menu keys, MAC lookup caching, recovery limits, and user-confirmed Proxmox behavior.

### Added

- A process-isolated test runner with timeouts, failure-reporting self-tests, required static checks, command coverage, JSON/JUnit reports, and CI artifact collection.
- Core and network transaction regressions covering configuration, recovery, CIM failures, asymmetric stores, privacy, and user input, plus a testing guide with dependency setup and live validation tracking.

### Validation

- Local Windows PowerShell 5.1: all 11 suites passed, including 130 named Pester tests and required static analysis.
- User-reported Proxmox Windows VM tests confirm profile and manual static reapplication, static-to-DHCP conversion, and DHCP-to-static profile application with the requested address, prefix, gateway, DNS order, and DHCP disabled.
- A failed gateway apply displayed successful recovery in the guest. Exact restored state and the remaining live checklist, including reboot persistence, still need verification.

## [2.9] - 2026-09-13

### Fixed

- Mask complete IPv6 addresses in logs, including compressed addresses, instead of leaving address segments visible.
- Keep log pseudonymization enabled when reading older consent files that specify otherwise.
- Correct privacy notices and documentation to describe the external MAC vendor lookup and GitHub update check.
- Stage and validate updates before replacing the running script; leave it intact if staging or backup fails.
- Prevent rapid successive backups from using the same filename.
- Reject abbreviated IPv4 addresses and invalid subnet masks before configuration.
- Suggest gateways that are inside the selected subnet, including narrow subnets and addresses outside the last octet.
- Clean up temporary copies and partial ZIP files when data export fails; use the Windows Desktop location even when it is redirected.
- Describe privacy controls in terms of actual script behavior rather than broad compliance claims.
- Save profiles through a validated temporary file, confirm replacement, and protect against different profile names mapping to the same filename.
- Clarify that the syntax checker verifies static quality, while live adapter behavior still needs release validation.
- Update checkout and SARIF upload actions to supported Node 24 versions for CI.

### Added

- Added a paged log viewer with literal message search, severity and date filters, and queries across rotated archives.
- Added an isolated log query regression check and included it in Windows PowerShell CI.
- Added isolated regression checks for IP masking, logging consent, updater failure paths, subnet suggestions, export cleanup, and profile replacement.
- Run these regression checks in CI under Windows PowerShell 5.1.

## [2.8] - 2026-07-04

### Added

- Added clearer non-admin startup messaging before the UAC prompt.
- Added graceful handling when elevation is denied or the elevated launch fails.
- Added PSScriptAnalyzer validation support for Windows PowerShell 5.1.
- Added internal helpers for adapter lookup, IPv4 summaries, safe local deletion, IPv4 address removal, DNS reset, gateway updates, and DHCP rollback.

### Changed

- Kept PSScriptAnalyzer clean with project settings tailored for this interactive console utility.
- Reduced repeated mutation logic in static IP, DHCP, rollback, and cleanup paths.
- Made file deletion behavior more consistent for logs, local data, and profile removal.
- Improved confirmation prompt spacing in high-traffic configuration flows.
- Updated the main status header so the selected adapter name appears only on the adapter line.

### Fixed

- Fixed analyzer findings for empty catch blocks and background job variable scoping.
- Fixed post-configuration DNS diagnostics so successful DNS configurations no longer produce false-positive notes.

## [2.7] - 2026-06

### Added

- Added modern JSON IP profiles with groups, descriptions, adapter metadata, and legacy XML fallback.
- Added DNS lookup, traceroute, TCP port check, and ARP table tools.
- Added managed log rotation with age/count retention.
- Added managed backup folder with capped update and network configuration backups.

### Changed

- Reworked the main menu into grouped Configuration, Diagnostics, and Tools sections.
- Bumped script requirement to PowerShell 5.1 and hardened compatibility-sensitive paths.
- Made DNS reachability checks quiet diagnostics unless action is needed.
- Added consistent `y/yes/n/no` confirmation prompts.
- Improved GDPR/privacy menu wording and behavior.

### Fixed

- Fixed subnet calculator blank/invalid input handling.
- Fixed JSON log escaping.
- Fixed PSScriptAnalyzer `$profile` automatic-variable warnings.

## [2.6] - 2026-01

### Added

- Added MAC vendor lookup with online API integration and local caching.
- Added advanced IP conflict detection with NetBIOS, ARP, ICMP, neighbor cache, TCP, and final ARP verification checks.
- Added multiple IP address cleanup to prevent APIPA address accumulation.

### Changed

- Optimized NetBIOS, ping, TCP, and conflict-detection timings.
- Improved UI/UX messaging, progress indicators, and pause behavior.
- Centralized version management.
- Improved PowerShell 5.1 compatibility.

### Fixed

- Fixed MAC vendor lookup caching failures.
- Fixed IP conflict detection for Windows clients.
- Fixed multiple IP address display issues in `Show-IPInfo`.
- Fixed APIPA addresses persisting after configuration changes.
- Fixed status bar concatenating multiple IP addresses.

## [2.5] - 2026-01

### Added

- Added pre-flight validation for IP, DNS, gateway, and null input checks.
- Added gateway subnet validation.
- Added smart gateway suggestions for broader prefix lengths.
- Added retry mechanisms for IP configuration and DNS setup.
- Added final state verification.
- Added automatic DNS cache clearing.
- Added adapter status warnings before configuration.
- Added enhanced logging with DEBUG, INFO, WARN, ERROR, and CRITICAL levels.

### Changed

- Improved DHCP disable workflow before applying static IP.
- Improved error messages and suggested actions.

### Fixed

- Fixed PolicyStore DHCP conflict errors.
- Added automatic rollback to DHCP when static IP configuration fails.

## [2.4] - 2026-01

### Added

- Added ARP lookup fallback for IP conflict detection.
- Added same-subnet-aware conflict warnings.
- Added validation to prevent setting IP to gateway, network, or broadcast addresses.
- Added warning for suspicious `.1` IP configurations.

### Changed

- Improved status line with interface state, link speed, IP, and configuration type.
- Optimized conflict check timeout.
- Improved menu visual hierarchy and console colors.
- Improved DHCP disable workflow for static IP reliability.

## [2.3] - 2025-12

### Added

- Added activity heartbeat indicator during live monitoring.
- Added MAC address display in status view.
- Added comprehensive event logging with GDPR pseudonymization.

### Changed

- Improved Wi-Fi network switching detection and messaging.
- Improved DHCP lease time calculations.
- Standardized timestamp colors.

### Fixed

- Fixed false DHCP renewal events.
- Fixed duplicate timestamp display.
- Fixed window title reset after monitoring exit.
- Fixed Wi-Fi status variable reference.
- Fixed hardcoded computer name in `Test-Connection`.
- Improved DHCP server change detection and logging.

## [2.2] - 2025

### Added

- Added initial live interface monitoring.
- Added real-time network event tracking.
- Added interactive diagnostics during monitoring.
- Added GDPR-compliant logging system.
