# AIO Malicious Extension Guard

AIO Malicious Extension Guard helps WordPress administrators monitor for known x-dav and fake-verification indicators, unexpected executable-file changes, and unapproved plugin changes. It provides controlled quarantine, evidence export, an optional early-boot MU guard, and scheduled monitoring.

## What it protects

- Scans executable files in standard plugin directories, must-use plugins, WordPress drop-ins, and uploads.
- Records a site-wide executable-file baseline after an administrator reviews a clean scan.
- Records a separate full-directory fingerprint for every standard plugin approval. Any regular file added, removed, or modified in that plugin directory invalidates the approval.
- Blocks activation of known malicious slugs and can optionally block unapproved plugins or all dashboard-driven plugin changes.
- Keeps critical findings in a protected quarantine rather than deleting them.

## Important limitations

This plugin reduces risk. It cannot guarantee protection after a hosting account, administrator account, deployment system, WordPress core, or plugin-update supply chain has been compromised. Malware with the same server permissions can alter or remove a normal WordPress plugin. Use MFA, least-privilege access, managed updates, a WAF, server-level scanning, and tested offsite backups alongside this plugin.

## Full-directory approval

The approved-plugin ledger is deliberately stricter than a main-file checksum. When an administrator approves inventory, AIO Malicious Extension Guard runs a fresh scan and creates a deterministic SHA-256 fingerprint from the path, checksum, and size of every regular file inside each plugin directory. Any file change requires a new review. Existing approvals from older releases are intentionally shown as requiring review because they did not include this full-directory fingerprint.

## False positives

See [docs/FALSE-POSITIVES.md](docs/FALSE-POSITIVES.md). Do not use the one-click cleanup button to resolve a review-level alert. Export evidence first, validate the finding, and restore only after a qualified reviewer documents why it is safe.

## Privacy and retention

See [PRIVACY.md](PRIVACY.md) and [docs/DATA-RETENTION.md](docs/DATA-RETENTION.md). AIO Malicious Extension Guard stores its monitoring data in the WordPress database. It does not send data to AIO Web Designs. Public-page monitoring is optional and only requests this site's own URLs.

On supported WordPress versions, the plugin contributes this disclosure to the site's built-in Privacy Policy guide. Site owners remain responsible for reviewing that suggested text and publishing an appropriate site privacy policy.

## Development

```bash
composer install
bash bin/install-wp-tests.sh wordpress_test root '' 127.0.0.1 latest
composer run lint
composer test
```

The test suite requires a WordPress test environment and MySQL. GitHub Actions runs WordPress Coding Standards and the integration suite against the supported PHP floor and a current PHP release. A successful CI run is required before a public release.

## Support and security reports

For normal support, see [SUPPORT.md](SUPPORT.md). For a potential security vulnerability, follow [SECURITY.md](SECURITY.md) and do not post exploit details in a public support request.

## Public releases

See [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md) for the required CI, staging, review, packaging, and WordPress.org submission gates.

## License

GPL-2.0-or-later. See [LICENSE](LICENSE).
