# Notes: main.js

## Authorization
- Target: main.js (1397-byte webpack bundle, webshop client), copied to original/.
- Owner: the user, who wrote it as a test target and stated authorization to analyze and run it.
- Environment: disposable arm64 Ubuntu VM, no internet. The user could not answer questions; assumptions are noted below.
- Purpose: module map and recovered API client.
- Dynamic runs used node with stubbed fetch/document, so no network request was made.

## Hypotheses
- H1: modules 10 and 633 are thin wrappers over request core 255. Supported by F-001, F-002.
- H2: the recovered client is behaviourally equivalent to the bundle's requests. Supported by F-001 (checked on ok and 401 scenarios).

## Summary
Bundle has 4 webpack modules: 255 HTTP core (base https://shop.example/api/v3, headers Content-Type and X-Client webshop/3.1, Bearer auth, throws on 401), 10 login, 633 orders (list/cancel), 766 DOM renderer. The entry point logs in with hardcoded demo-user/demo-pass, lists orders and wires click-to-cancel. The recovered client is in recovered/api_client.js and its requests match the original under a stubbed fetch.

## Gaps
- Server response schemas are unknown (only token, and order id/total, are used). Next: capture real or mock server traffic.
- The hardcoded demo credentials were not redacted since they are the user's test values.
- Assumed the DOM is a browser one; module 766 was only run against a stub document.
- Test covers 401 only on /orders; 401 on login uses the same code path but was not separately run.

## Session log
### 2026-11-06
- Did: triage, webcrack, endpoint scan, wrote client and differential harness.
- Showed: F-001..F-003 confirmed.
- Next: none required.
