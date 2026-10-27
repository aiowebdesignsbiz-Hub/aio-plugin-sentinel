=== AIO Malicious Extension Guard ===
Contributors: aiowebdesigns
Tags: security, malware, x-dav, integrity
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 5.6.0
License: GPL-2.0-or-later

Detects x-dav and fake-verification indicators, blocks malicious extensions, and provides controlled quarantine and integrity monitoring.

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

AIO Malicious Extension Guard keeps scan results, integrity hashes, approval records, configured notification recipients, and audit data in the local WordPress database. It does not send that data to AIO Web Designs. Public-page monitoring is optional and only requests this site's own URLs.

Records are retained on uninstall by default. An administrator may opt in to delete AIO Malicious Extension Guard database records on uninstall from Tools > AIO Malicious Extension Guard. The quarantine directory and MU guard are intentionally never removed automatically so they remain available for review.

AIO Malicious Extension Guard has no telemetry or remote code delivery. Its only optional network request is public-page monitoring, which is off by default and checks this site's own URLs. Notification emails use the site's configured WordPress mail service only after an administrator configures or accepts the site administrator recipient.

The plugin also adds this disclosure to WordPress's built-in Privacy Policy guide under Settings > Privacy, so site owners can include accurate local data-handling information in their policy.

== Installation ==

1. Zip the `aio-malicious-extension-guard` directory.
2. In WordPress, go to Plugins > Add New > Upload Plugin.
3. Upload the ZIP and activate it.
4. Go to Tools > AIO Malicious Extension Guard and run the first scan.
5. Configure the scan interval, notification recipients, and any approved administrator accounts.

== Updates and settings ==

AIO Malicious Extension Guard updates are non-destructive. Replacing an older version with a newer AIO Malicious Extension Guard ZIP keeps the website's existing settings, scan schedule, notification recipients, approved administrator list, integrity baseline, latest scan results, and cleanup audit log. New releases only add defaults for settings that did not exist in earlier versions.

== Hardening ==

After the initial clean scan, create a baseline from Tools > AIO Malicious Extension Guard. Review and refresh it only after approved plugin changes. For a stronger operational control, test and then add `define( 'DISALLOW_FILE_MODS', true );` to wp-config.php; this disables dashboard plugin and theme installs, updates, and edits.

The plugin automatically installs `mu-plugin/aio-plugin-sentinel-guard.php` to `wp-content/mu-plugins/aio-plugin-sentinel-guard.php` during activation and verifies it after updates. Tools > AIO Malicious Extension Guard also provides Install or Repair and Download buttons. If your host prevents WordPress from writing to the MU plugins folder, download the guard there and upload it to that exact location. This companion has no settings page and intentionally starts before ordinary plugins.

== Changelog ==

= 5.6.0 =
* Renamed the public package to AIO Malicious Extension Guard and adopted the reserved WordPress.org slug and text domain.
* Replaced generic public identifiers with the distinct AIOMEG prefix.
* Added a one-time, non-destructive import of AIO Sentinel settings, scan history, baseline, approvals, alerts, and audit records.
* Derived the standard plugins directory from the installed plugin path for compatibility with custom WordPress content directories.

= 5.5.1 =
* Fixed false-positive malware findings for the expected AIO Malicious Extension Guard MU guard and files retained in AIO Malicious Extension Guard quarantine.
* The expected MU-guard path is now excluded from pattern scanning because it deliberately contains known malicious plugin identifiers. Its checksum remains independently verified through Protection Health and a changed guard remains a critical condition.
* Hardened quarantine-path detection on hosts with inconsistent filesystem path resolution, so retained evidence is not re-scanned as active executable uploads.

= 5.5.0 =
* Added a clear animated scan-in-progress state and outcome toasts. Green results distinguish a completed scan with no known critical malware indicators from review-level items; red results list critical locations needing investigation.
* Added a first-run security gate. New installations show only Run Initial Scan until the plugin has inspected the site, so unreviewed plugins cannot be accidentally approved before the first security check.
* Automatically records the active AIO Malicious Extension Guard package in the local approval ledger after each completed scan. No other plugin is automatically trusted.
* Hides all plugin-approval controls while critical findings are present, preventing accidental approval of a suspicious plugin.
* Cleanup completion notices now state how many critical items were moved to protected quarantine and clearly distinguish quarantine errors that need follow-up.

= 5.4.5 =
* Replaced the browser confirmation popup for incident cleanup with a visible, required server-validated acknowledgment. This is clearer for administrators and avoids popup interruptions while keeping explicit approval before quarantine.

= 5.4.4 =
* Improved incident cleanup on hosts where the WordPress filesystem transport is slow or unavailable. Quarantine now prefers a validated direct, atomic move and falls back to the WordPress filesystem API only when needed.
* Writes quarantine protection files and the audit record without requiring the filesystem transport, while retaining the existing WordPress fallback.

= 5.4.3 =
* Clearly identifies critical scan findings as the reason plugin approvals are temporarily unavailable, instead of allowing a blocked save to look like an approval-record issue.
* Disables the inventory approval action until current critical findings are resolved or quarantined, and lists the exact blockers with the controlled-cleanup path.
* Returns a count-specific server-side explanation if a fresh scan detects new critical findings during approval.

= 5.4.2 =
* Clarified that a scan alone does not approve plugins and renamed the inventory action to Save Selected Plugin Approvals.
* Removed the redundant browser confirmation from the approval action; the server-validated review acknowledgment and fresh-scan gate remain required.
* Verifies that selected approval records persist before reporting approval success.

= 5.4.1 =
* Fixed the plugin-inventory approval and revoke forms to render WordPress security tokens directly instead of applying unnecessary output filtering.
* Sends explicit no-cache headers on the AIO Malicious Extension Guard administration screen to avoid stale browser or host-cached approval tokens.

= 5.4.0 =
* Replaced the all-or-nothing inventory approval action with selectable per-plugin approval controls.
* Moved current approved plugins into a compact, expandable Previously Approved Plugins section with a safe revoke-approval action that never changes the plugin itself.
* Keeps changed or newly discovered plugins in the primary review list so the approval screen stays focused on actionable work.

= 5.3.3 =
* Added a narrowly scoped signature for the verified WP Asset Cache malware family: its CFX command-and-control identifiers and persistence markers are now critical findings.
* Added `asset-cache` to the regular-plugin and early-boot MU guard blocklists, preventing known reuse of that malicious identifier.

= 5.3.2 =
* Prevented the verified AIO Malicious Extension Guard MU guard from being reported as malware by its own signature scan.
* Excluded retained AIO Malicious Extension Guard quarantine folders from upload scanning so quarantined evidence cannot generate recursive alerts.

= 5.3.1 =
* Shortened the repository summary to meet the WordPress.org readme limit.

= 5.3.0 =
* Renamed the public listing to AIO Malicious Extension Guard and updated the WordPress.org packaging to comply with repository naming rules.
* Replaced direct filesystem writes with WordPress's filesystem abstraction and moved new quarantine data to the uploads directory.
* Retained legacy quarantine records for review and restoration after updating.
* Resolved translation-context, readme, and administrative-request static-analysis findings.

= 5.2.1 =
* Hardened administrative security-action request handling and added an automated compatibility test matrix for supported WordPress and PHP versions.
* Improved the release test workflow used to validate clean installs, settings retention, and update behavior.

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
* Added AIO Web Designs branding and a direct link to aiowebdesigns.com in the AIO Malicious Extension Guard tools screen.

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
