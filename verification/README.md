# Verification

Executed on 21 October 2026 with Zanity 0.1.26, all deterministic rules selected, and warnings treated as failures. The downloaded binary matched the SHA-256 in its GitHub release metadata.

- `checks.txt`: complete local gate output.
- `zanity.json`: raw findings array; empty means zero findings.
- `result.json`: checker version, provenance and scope.
- `demo.txt`: actual demo output, including simulated hook events and real Git history.

No live Claude Code binary was available. Model-based Zanity inference was not run. Production type checking covers `hdr/`; pytest executes the test suite. GitHub Actions configuration is included but has not run remotely.
