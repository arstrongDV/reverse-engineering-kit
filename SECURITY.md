# Security Policy

## Reporting a vulnerability

Please report security problems privately through the **Security** tab of this repository
(Report a vulnerability), not in a public issue. Expect a first reply within 48 hours.

## What counts

Report anything that breaks the guarantees below, for example a script that writes outside its
work directory, runs a target, or reaches the network.

## Script guarantees

Every script in `skills/reverse-engineering-kit/scripts/`:

- never executes the target
- never downloads anything or makes network requests
- never modifies `original/`
- writes only inside `re-work/<target>/`
- never installs software: install hints are plain text that you run yourself

The Frida templates in `scripts/frida/` instrument a running process, so they are not covered by
the first guarantee. Use them only inside a VM you control, on targets you are authorized to test.
