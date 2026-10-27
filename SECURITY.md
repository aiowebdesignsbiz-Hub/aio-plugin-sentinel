# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities in AIO Malicious Extension Guard privately to AIO Web Designs through the contact form at https://aiowebdesigns.com/. Include the plugin version, affected WordPress and PHP versions, clear reproduction steps, and a minimally sufficient proof of concept. Do not include live credentials or publish exploit details before a fix is available.

## Security review controls

Every release should receive the following review before distribution:

1. Run WordPress Coding Standards and the WordPress integration tests.
2. Review all capability checks, nonces, input sanitization, escaping, filesystem path validation, and quarantine behavior.
3. Confirm the package contains no credentials, development dependencies, or remote executable-code loading.
4. Review changes to blocked indicators and public-page matching language for false-positive risk.
5. Install the ZIP on a staging WordPress site, verify update retention, scheduled scans, approval workflow, evidence export, and restore-without-activation behavior.

This process improves assurance but is not a substitute for an independent penetration test or a host-level incident response investigation.
