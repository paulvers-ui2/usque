# Security policy

usque runs inside AuroraVPN (paulvers-ui2/rethink-app-masque) and carries its
WARP / MASQUE traffic. Report vulnerabilities **privately**: Security →
Report a vulnerability on this repository. Please do not open public issues.

Response targets, scope and the full security program are shared with the
app: see `SECURITY.md` and `docs/security/` in paulvers-ui2/rethink-app-masque.

CI (`.github/workflows/security.yml`): race-detector tests, govulncheck
(blocking on reachable vulnerabilities), gosec, CodeQL (security-extended)
and a full-history gitleaks scan, on every PR and weekly.
