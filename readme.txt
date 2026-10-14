=== AIO Plugin Sentinel ===
Contributors: aiowebdesigns
Tags: security, malware, plugin, x-dav
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 5.2.0
License: GPL-2.0-or-later

Detects known malicious plugin indicators associated with the x-dav/fake Cloudflare verification incident, blocks activation of confirmed malicious directory names, and offers a controlled quarantine workflow.

== What it does ==

* Scans plugin folders, must-use plugins, WordPress drop-ins, and executable files found in uploads.
* Blocks activation and upgrades of known malicious plugin directory names.
* Records an explicit, administrator-approved SHA-256 integrity baseline and reports code-file changes.
* Includes an optional change lock to prevent new plugin activation and plugin updates until the lock is removed.
* Automatically installs and verifies the standalone companion MU guard, which blocks known incident slugs before regular plugins load.
* Runs WordPress cron scans every 15 minutes, hourly, twice daily, or daily, plus after plugin updates.
* Sends deduplicated alerts to the site administrator and any configured security recipients.
* Lets a qualified administrator move a suspicious plugin into a protected quarantine directory instead of deleting it immediately.
* Provides a one-click incident cleanup that fresh-scans and quarantines critical findings. Administrator removal is optional and restricted to accounts excluded from an explicit approval list.
* Retains all site-specific monitoring settings, recipient lists, baseline data, scan history, and audit logs when the plugin is updated or replaced with a newer version.
* Adds an opt-in approved-plugin ledger that can block activation of plugins not explicitly reviewed for that site, using a full-directory fingerprint rather than only each plugin's main file.
* Checks the MU guard, scheduled scan, and scan freshness for tampering or scheduling failures.
* Can monitor the public homepage and chosen public URLs for the fake verification language used by x-dav campaigns.
* Exports a reviewable security evidence report and supports a deliberate, non-activating restore of a quarantined item.
* Summarizes WordPress-reported core and plugin updates without representing update availability as a vulnerability verdict.

== Important limitations ==

No WordPress plugin can guarantee prevention after a server, administrator account, deployment system, or plugin-update supply chain has been compromised. Malware running with the same web-server permissions can alter or remove a normal plugin. Use this with a web application firewall, least-privilege hosting access, MFA, offsite backups, controlled updates, and server-level malware scanning.

== False-positive workflow ==

Review-level findings are not automatically quarantined. Export the evidence report, compare the file with a known-good vendor package, confirm the publisher and release source, and document the decision. If a critical finding was quarantined and is confirmed safe, use Restore Without Activating, test it in staging, and reactivate only after qualified review. Do not refresh a baseline simply to suppress an alert.

== Privacy and retention ==

Plugin Sentinel keeps scan results, integrity hashes, approval records, configured notification recipients, and audit data in the local WordPress database. It does not send that data to AIO Web Designs. Public-page monitoring is optional and only requests this site's own URLs.

Records are retained on uninstall by default. An administrator may opt in to delete Plugin Sentinel database records on uninstall from Tools > Plugin Sentinel. The quarantine directory and MU guard are intentionally never removed automatically so they remain available for review.

Plugin Sentinel has no telemetry or remote code delivery. Its only optional network request is public-page monitoring, which is off by default and checks this site's own URLs. Notification emails use the site's configured WordPress mail service only after an administrator configures or accepts the site administrator recipient.

The plugin also adds this disclosure to WordPress's built-in Privacy Policy guide under Settings > Privacy, so site owners can include accurate local data-handling information in their policy.

== Installation ==

1. Zip the `aio-plugin-sentinel` directory.
2. In WordPress, go to Plugins > Add New > Upload Plugin.
3. Upload the ZIP and activate it.
4. Go to Tools > Plugin Sentinel and run the first scan.
5. Configure the scan interval, notification recipients, and any approved administrator accounts.

== Updates and settings ==

Plugin Sentinel updates are non-destructive. Replacing an older version with a newer AIO Plugin Sentinel ZIP keeps the website's existing settings, scan schedule, notification recipients, approved administrator list, integrity baseline, latest scan results, and cleanup audit log. New releases only add defaults for settings that did not exist in earlier versions.

== Hardening ==

After the initial clean scan, create a baseline from Tools > Plugin Sentinel. Review and refresh it only after approved plugin changes. For a stronger operational control, test and then add `define( 'DISALLOW_FILE_MODS', true );` to wp-config.php; this disables dashboard plugin and theme installs, updates, and edits.

The plugin automatically installs `mu-plugin/aio-plugin-sentinel-guard.php` to `wp-content/mu-plugins/aio-plugin-sentinel-guard.php` during activation and verifies it after updates. Tools > Plugin Sentinel also provides Install or Repair and Download buttons. If your host prevents WordPress from writing to the MU plugins folder, download the guard there and upload it to that exact location. This companion has no settings page and intentionally starts before ordinary plugins.

== Changelog ==

= 5.2.0 =
* Added WordPress Privacy Policy guide content that explains local data storage, the opt-in same-site page check, notification emails, retention, and deletion choices.
* Added official AIO Web Designs plugin and author links in the WordPress plugin header.
* Repaired the GitHub Actions workflow placement, enabled WordPress.org language-pack loading, and expanded public-release repository documentation and asset guidance.

= 5.1.0 =
* Upgraded approved-plugin verification from a main-file checksum to a deterministic full-directory fingerprint covering every regular file in each standard plugin directory.
* Added a fresh-scan gate and server-validated administrator acknowledgment before recording a reviewed plugin inventory.
* Added opt-in uninstall data deletion while retaining quarantined files and the early-boot MU guard by design.
* Added documented false-positive, privacy, data-retention, support, security-review, PHPUnit, coding-standard, and CI workflows for the public repository.

= 5.0.1 =
* Reworked security notification emails with an AIO-branded HTML layout and clear, calm messaging for non-critical integrity changes.
* Integrity-only notifications now confirm that no known infection or reinfection was found and that no immediate action is required.
* Added an administrator-only branded test-email option that does not run a scan or change site settings.

 = 5.0.0 =
* Added opt-in approved-plugin inventory controls, activation enforcement, and approval-change reporting.
* Added MU guard, WP-Cron, scan freshness, and configuration health checks with security alerts.
* Added optional public-page monitoring for x-dav/fake-verification patterns.
* Added security evidence export and controlled quarantine restore support; restored plugins are never reactivated automatically.
* Added a clearly labeled WordPress update-exposure summary.

 = 4.2.0 =
* Explicitly preserves and migrates site settings without overwriting existing choices during activation, reactivation, or ZIP replacement.
* Displays the new integrity baseline as clean immediately after it is created.
* Added AIO Web Designs branding and a direct link to aiowebdesigns.com in the Plugin Sentinel tools screen.

 = 4.1.2 =
* Reports one critical finding per blocked plugin directory, matching the directory-level quarantine action.
* Avoids a second full-filesystem scan after cleanup; the saved results are updated immediately and the next scheduled scan provides independent verification.

 = 4.1.1 =
* Assigned unique form control IDs for all administrative actions to prevent ambiguous action targeting.

 = 4.1.0 =
* Automatically installs, verifies, updates, and safely backs up the early-boot MU guard.
* Added one-click MU guard repair and direct download controls.
* Added activation-persistence filtering to the MU guard for exact known-malicious plugin names.

 = 4.0.0 =
* Added configurable WP-Cron scanning and post-update scanning.
* Added configurable multi-recipient security alerts with deduplication.
* Added one-click incident cleanup, protected quarantine audit logging, and opt-in approved-admin cleanup.
* Added optional automatic containment for exact known-malicious plugin names.

= 0.3.0 =
* Added standalone must-use early-boot guard for known malicious plugin slugs.

= 0.2.0 =
* Added must-use plugin, drop-in, and uploads coverage.
* Added administrator-approved SHA-256 integrity baselines.
* Added optional change lock and critical-finding email alerts.

= 0.1.0 =
* Initial incident-response scanner and controlled quarantine workflow.
