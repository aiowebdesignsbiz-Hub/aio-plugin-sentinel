<?php
/**
 * Plugin uninstall behavior.
 *
 * Site security records are retained unless an administrator explicitly opted
 * into deletion in AIO Sentinel settings before uninstalling the plugin.
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

$settings = get_option( 'aio_ps_settings', array() );
wp_clear_scheduled_hook( 'aio_ps_scheduled_scan' );

if ( empty( $settings['delete_data_on_uninstall'] ) ) {
	return;
}

foreach ( array(
	'aio_ps_settings',
	'aio_ps_last_alert_fingerprint',
	'aio_ps_cleanup_log',
	'aio_ps_mu_guard_status',
	'aio_ps_scan_results',
	'aio_ps_integrity_baseline',
	'aio_ps_plugin_approvals',
	'aio_ps_health_status',
	'aio_ps_external_monitor_results',
) as $option ) {
	delete_option( $option );
	if ( is_multisite() ) {
		delete_site_option( $option );
	}
}

// The MU guard and quarantine directory are intentionally retained for review.
