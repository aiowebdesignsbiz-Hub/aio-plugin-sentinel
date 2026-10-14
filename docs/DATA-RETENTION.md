# Data Retention and Uninstall Policy

## Default behavior

Removing or deactivating Plugin Sentinel does not delete its records by default. Retaining the scan baseline, approvals, findings, and cleanup history helps support incident review and prevents evidence from being lost during a rushed response.

The scheduled scan hook is always cleared when the plugin is uninstalled.

## Optional deletion

An administrator can enable **Delete Plugin Sentinel data when the plugin is uninstalled** in Tools > Plugin Sentinel. When enabled, uninstall deletes these WordPress options:

- Settings and email-recipient configuration.
- Latest scan results and integrity baseline.
- Approved plugin inventory.
- Alert fingerprint, health data, public-page monitoring results, and cleanup audit log.

## Intentionally retained items

The plugin never automatically deletes `wp-content/aio-plugin-sentinel-quarantine` or `wp-content/mu-plugins/aio-plugin-sentinel-guard.php`. Those files may be required for evidence review or for continued blocking of known malicious plugin identifiers after the normal plugin has been removed. A qualified administrator must remove them deliberately through the host file manager after review.
