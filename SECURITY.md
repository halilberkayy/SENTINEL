# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 6.0.x   | ✅        |
| < 6.0   | ❌        |

## Reporting a vulnerability

**Do not open a public issue for security vulnerabilities.**

Report privately through GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability):

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Include:
   - Affected component (module, API endpoint, file path).
   - Reproduction steps or a proof of concept.
   - Impact assessment and, if known, a suggested fix.

### Response targets

| Stage | Target |
|-------|--------|
| Acknowledgement | within 72 hours |
| Triage + severity | within 7 days |
| Fix or mitigation plan | within 30 days (severity dependent) |

We will keep you updated through the advisory and credit you in the release notes unless you prefer to remain anonymous.

## Scope

In scope:

- Authentication / authorization bypass in the API or web UI.
- Injection, SSRF, or RCE in SENTINEL's own code (not the vulnerabilities it is designed to detect in targets).
- Secret leakage, insecure defaults, or sandbox escapes in the scanner engine.
- Supply chain issues in declared dependencies.

Out of scope:

- Findings produced *by* SENTINEL against third-party targets (report those to the target's owner).
- Results from scanning systems you are not authorized to test.
- Missing hardening on a deployment you control.

## Responsible use

SENTINEL sends HTTP requests to a host you name. Use it only on systems you are
allowed to test. Scanning anything else is not a vulnerability in SENTINEL.
