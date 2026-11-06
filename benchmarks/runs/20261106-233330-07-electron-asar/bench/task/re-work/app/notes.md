# Notes: app.asar

## Authorization
Target: resources/app.asar, a test Electron app written by the user. Owner: the user (stated in the request). Permission: user authorized analysis and running it, in a disposable arm64 Ubuntu VM with no internet. Purpose: extracted sources and an IPC map. Assumption: I analyze statically and do not run it unless needed.

## Hypotheses
- H1: the app registers ipcMain handlers that a preload bridge exposes. Open.

## Summary
rekit-benchmark-notes 1.4.0 is a small Electron notes app (6 files, extracted to decompiled/js/app/, no minification or source map). It has 5 IPC channels, all bridged through preload as window.notes; contextIsolation is on and nodeIntegration is unset. Observations: handlers do not validate event.sender or payload (notes:save stores any object fields, spread then id overwritten); store is in-memory only.

## Gaps
- Not run dynamically (static source was fully readable, so assumed unnecessary). Next: launch in the VM and call each channel to observe behavior.
- Does not set sandbox/CSP explicitly; Electron defaults apply by version, and the Electron version is unknown (no binary supplied).

## Session log

### 2026-11-06
- Did: extracted asar, mapped IPC, verified with tests/check_ipc.py.
- Showed: F-001, F-002 confirmed.
- Next: optional dynamic run.
