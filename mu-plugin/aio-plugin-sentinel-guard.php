<?php
/**
 * Plugin Name: AIO Sentinel Guard
 * Description: Must-use early boot guard for known malicious plugin identifiers.
 * Version: 4.1.0
 * Author: AIO Web Designs
 */

defined( 'ABSPATH' ) || exit;

/*
 * This file is intentionally standalone. Copy it directly to wp-content/mu-plugins/
 * so WordPress loads it before ordinary plugins.
 */
function aio_ps_guard_blocked_slugs() {
	return array(
		'xdav-tracker',
		'xdav-trackerd',
		'google-api-updates',
		'responsive-block-suite',
		'suspicious-plugin-cleaner',
		'block-lab-pro',
	);
}

function aio_ps_guard_filter_active_plugins( $plugins ) {
	if ( ! is_array( $plugins ) ) {
		return $plugins;
	}
	$blocked = aio_ps_guard_blocked_slugs();
	$filtered = array_filter( $plugins, function( $plugin ) use ( $blocked ) {
		$parts = explode( '/', ltrim( (string) $plugin, '/' ) );
		if ( empty( $parts[0] ) ) {
			return true;
		}
		$slug = count( $parts ) > 1 ? $parts[0] : pathinfo( $parts[0], PATHINFO_FILENAME );
		return ! in_array( strtolower( $slug ), $blocked, true );
	} );
	return array_values( $filtered );
}

function aio_ps_guard_filter_network_plugins( $plugins ) {
	if ( ! is_array( $plugins ) ) {
		return $plugins;
	}
	$blocked = aio_ps_guard_blocked_slugs();
	foreach ( array_keys( $plugins ) as $plugin ) {
		$parts = explode( '/', ltrim( (string) $plugin, '/' ) );
		$slug = empty( $parts[0] ) ? '' : ( count( $parts ) > 1 ? $parts[0] : pathinfo( $parts[0], PATHINFO_FILENAME ) );
		if ( $slug && in_array( strtolower( $slug ), $blocked, true ) ) {
			unset( $plugins[ $plugin ] );
		}
	}
	return $plugins;
}

add_filter( 'option_active_plugins', 'aio_ps_guard_filter_active_plugins', PHP_INT_MAX );
add_filter( 'site_option_active_sitewide_plugins', 'aio_ps_guard_filter_network_plugins', PHP_INT_MAX );

/* Reject known malicious identifiers before WordPress persists plugin activation. */
add_filter( 'pre_update_option_active_plugins', 'aio_ps_guard_filter_active_plugins', PHP_INT_MAX );
add_filter( 'pre_update_site_option_active_sitewide_plugins', 'aio_ps_guard_filter_network_plugins', PHP_INT_MAX );
