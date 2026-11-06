# Reverse Engineering Report: app

- **SHA-256:** 74b824d85724dc50e5fc19d70cb838c531bcff4bb0e584f16609c2388e4b6449
- **Authorization:** Target: resources/app.asar, a test Electron app written by the user. Owner: the user (stated in the request). Permission: user authorized analysis and running it, in a disposable arm64 Ubuntu VM with no internet. Purpose: extracted sources and an IPC map. Assumption: I analyze statically and do not run it unless needed.
- **Generated:** 2026-11-06 22:33 UTC

## Summary

rekit-benchmark-notes 1.4.0 is a small Electron notes app (6 files, extracted to decompiled/js/app/, no minification or source map). It has 5 IPC channels, all bridged through preload as window.notes; contextIsolation is on and nodeIntegration is unset. Observations: handlers do not validate event.sender or payload (notes:save stores any object fields, spread then id overwritten); store is in-memory only.

## Confirmed findings

- **F-001** Main process registers 5 IPC channels: notes:list/save/delete, app:version (handle) and window:minimize (on)
  - Location: main.js:12-16
  - Evidence: ipcMain.handle/on calls
  - Verified by: tests/check_ipc.py, a behavior check: 4 cases passed, none failed
- **F-002** Preload exposes window.notes via contextBridge, mapping to those 5 channels; contextIsolation true, nodeIntegration unset
  - Location: preload.js:3-9; main.js:7
  - Evidence: contextBridge.exposeInMainWorld
  - Verified by: tests/check_ipc.py, a behavior check: 4 cases passed, none failed

## Observed findings

None.

## Inferred findings

None.

## Gaps and next experiments

- Not run dynamically (static source was fully readable, so assumed unnecessary). Next: launch in the VM and call each channel to observe behavior.
- Does not set sandbox/CSP explicitly; Electron defaults apply by version, and the Electron version is unknown (no binary supplied).

## Retracted findings

None.
