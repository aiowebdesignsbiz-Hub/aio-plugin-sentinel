<?php
/**
 * Plugin uninstall behavior.
 *
 * Site security records are retained unless an administrator explicitly opted
 * into deletion in AIO Malicious Extension Guard settings before uninstalling the plugin.
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

$settings = get_option( 'aiomeg_settings', array() );
wp_clear_scheduled_hook( 'aiomeg_scheduled_scan' );

if ( empty( $settings['delete_data_on_uninstall'] ) ) {
	return;
}

foreach ( array(
	'aiomeg_settings',
	'aiomeg_last_alert_fingerprint',
	'aiomeg_cleanup_log',
	'aiomeg_mu_guard_status',
	'aiomeg_scan_results',
	'aiomeg_integrity_baseline',
	'aiomeg_plugin_approvals',
	'aiomeg_health_status',
	'aiomeg_external_monitor_results',
) as $option ) {
	delete_option( $option );
	if ( is_multisite() ) {
		delete_site_option( $option );
	}
}

// The MU guard and quarantine directory are intentionally retained for review.
