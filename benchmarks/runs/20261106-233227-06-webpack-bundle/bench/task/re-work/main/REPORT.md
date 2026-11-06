# Reverse Engineering Report: main

- **SHA-256:** 817db934bbe698b269763c3da5e8014fe58428b54274b3bb5ccb2f1de0642d68
- **Authorization:** - Target: main.js (1397-byte webpack bundle, webshop client), copied to original/. - Owner: the user, who wrote it as a test target and stated authorization to analyze and run it. - Environment: disposable arm64 Ubuntu VM, no internet. The user could not answer questions; assumptions are noted below. - Purpose: module map and recovered API client. - Dynamic runs used node with stubbed fetch/document, so no network request was made.
- **Generated:** 2026-11-06 22:32 UTC

## Summary

Bundle has 4 webpack modules: 255 HTTP core (base https://shop.example/api/v3, headers Content-Type and X-Client webshop/3.1, Bearer auth, throws on 401), 10 login, 633 orders (list/cancel), 766 DOM renderer. The entry point logs in with hardcoded demo-user/demo-pass, lists orders and wires click-to-cancel. The recovered client is in recovered/api_client.js and its requests match the original under a stubbed fetch.

## Confirmed findings

- **F-001** Module 255 is the request core: fetch to https://shop.example/api/v3+path, JSON headers, X-Client webshop/3.1, optional Bearer token, throws 'session expired' on 401
  - Location: original/main.js module 255
  - Evidence: read source; run under stubbed fetch
  - Verified by: tests/check_client.py, a function check: 3 cases passed, none failed
- **F-002** Module 10 login: POST /auth/login body {username,password}; 633 listOrders: GET /orders?limit=50 (Bearer); cancelOrder: POST /orders/{id}/cancel (Bearer)
  - Location: original/main.js modules 10, 633
  - Evidence: read source; literal paths
  - Verified by: tests/check_client.py, an endpoint check: 3 cases passed, none failed
- **F-003** Module map: 255 http core; 10 auth; 633 orders; 766 DOM order-list renderer (click -> cancel); entry IIFE logs in with hardcoded demo-user/demo-pass, lists orders, wires click to cancel
  - Location: original/main.js
  - Evidence: read source
  - Verified by: tests/check_client.py, a behavior check: 3 cases passed, none failed

## Observed findings

None.

## Inferred findings

None.

## Gaps and next experiments

- Server response schemas are unknown (only token, and order id/total, are used). Next: capture real or mock server traffic.
- The hardcoded demo credentials were not redacted since they are the user's test values.
- Assumed the DOM is a browser one; module 766 was only run against a stub document.
- Test covers 401 only on /orders; 401 on login uses the same code path but was not separately run.

## Retracted findings

None.
