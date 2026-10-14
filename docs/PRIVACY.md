# Privacy Policy

## Data stored locally

AIO Sentinel stores the following data in the WordPress database for the site where it is installed:

- Scan timestamps, findings, and executable-file integrity hashes.
- The approved plugin inventory, including plugin paths, versions, file fingerprints, and the administrator login that recorded approval.
- Notification recipient email addresses configured by an administrator.
- Scan-health status, public-page monitoring status codes and matching indicator words, and cleanup audit records.

The plugin does not store copies of public-page response bodies. It does not send scan results, WordPress users, credentials, or files to AIO Web Designs or another third party.

## Network requests and emails

Public-page monitoring is off by default. When enabled, it requests only the WordPress site's own homepage and administrator-supplied URLs on the same host to look for fake-verification patterns. Email notifications are sent through the WordPress site's configured mail system to the site administrator and any recipients configured by an administrator.

## Retention and removal

Monitoring records remain on uninstall by default so an incident can be reviewed after the plugin is removed. An administrator can opt into deleting AIO Sentinel settings, records, baseline, approval ledger, health data, and cleanup audit log during uninstall. Quarantined files and the standalone MU guard are never deleted automatically.

See [docs/DATA-RETENTION.md](docs/DATA-RETENTION.md) for the complete deletion list.
