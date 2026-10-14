<?php

defined( 'ABSPATH' ) || exit;

/**
 * Site-level checks that complement the filesystem scanner without storing page content.
 */
class AIO_PS_Monitor {

	const OPTION_APPROVALS = 'aio_ps_plugin_approvals';
	const OPTION_HEALTH = 'aio_ps_health_status';
	const OPTION_EXTERNAL = 'aio_ps_external_monitor_results';

	public static function plugin_inventory() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$plugins = get_plugins();
		$active = (array) get_option( 'active_plugins', array() );
		$network_active = is_multisite() ? array_keys( (array) get_site_option( 'active_sitewide_plugins', array() ) ) : array();
		$approvals = (array) get_option( self::OPTION_APPROVALS, array() );
		$inventory = array();
		foreach ( $plugins as $plugin_file => $plugin ) {
			$path = WP_PLUGIN_DIR . '/' . $plugin_file;
			$hash = is_readable( $path ) ? hash_file( 'sha256', $path ) : false;
			$directory = self::plugin_directory_fingerprint( $plugin_file );
			$approval = isset( $approvals[ $plugin_file ] ) && is_array( $approvals[ $plugin_file ] ) ? $approvals[ $plugin_file ] : array();
			$approved = ! empty( $approval['sha256'] ) && ! empty( $approval['directory_sha256'] ) && $hash && ! empty( $directory['sha256'] ) && ! empty( $directory['complete'] ) && hash_equals( (string) $approval['sha256'], (string) $hash ) && hash_equals( (string) $approval['directory_sha256'], (string) $directory['sha256'] ) && isset( $approval['version'] ) && (string) $approval['version'] === (string) $plugin['Version'];
			$inventory[ $plugin_file ] = array(
				'file' => $plugin_file,
				'name' => isset( $plugin['Name'] ) ? $plugin['Name'] : $plugin_file,
				'version' => isset( $plugin['Version'] ) ? $plugin['Version'] : '',
				'sha256' => $hash,
				'active' => in_array( $plugin_file, $active, true ) || in_array( $plugin_file, $network_active, true ),
				'approved' => $approved,
				'approved_at' => isset( $approval['approved_at'] ) ? $approval['approved_at'] : '',
				'approved_by' => isset( $approval['approved_by'] ) ? $approval['approved_by'] : '',
				'directory_sha256' => isset( $directory['sha256'] ) ? $directory['sha256'] : '',
				'directory_file_count' => isset( $directory['file_count'] ) ? $directory['file_count'] : 0,
				'directory_complete' => ! empty( $directory['complete'] ),
			);
		}
		ksort( $inventory );
		return $inventory;
	}

	public static function approve_current_inventory() {
		$inventory = self::plugin_inventory();
		$approvals = (array) get_option( self::OPTION_APPROVALS, array() );
		$user = wp_get_current_user();
		foreach ( $inventory as $plugin_file => $plugin ) {
			if ( empty( $plugin['sha256'] ) ) {
				continue;
			}
			$approvals[ $plugin_file ] = array(
				'version' => $plugin['version'],
				'sha256' => $plugin['sha256'],
				'directory_sha256' => $plugin['directory_sha256'],
				'directory_file_count' => $plugin['directory_file_count'],
				'approved_at' => current_time( 'mysql', true ),
				'approved_by' => $user && $user->exists() ? $user->user_login : '',
			);
		}
		update_option( self::OPTION_APPROVALS, $approvals, false );
		return count( $inventory );
	}

	/**
	 * Builds a stable, full-directory fingerprint for a standard plugin. Every
	 * regular file is represented by its relative path, SHA-256 checksum, and size.
	 * Symlinks are ignored so an installed plugin cannot expand this scan beyond its
	 * own directory.
	 */
	public static function plugin_directory_fingerprint( $plugin_file ) {
		$plugin_file = ltrim( (string) $plugin_file, '/' );
		$plugin_path = WP_PLUGIN_DIR . '/' . $plugin_file;
		$root = false !== strpos( $plugin_file, '/' ) ? dirname( $plugin_path ) : $plugin_path;
		if ( ! file_exists( $root ) ) {
			return array( 'sha256' => '', 'file_count' => 0, 'complete' => false );
		}

		if ( is_file( $root ) ) {
			$hash = @hash_file( 'sha256', $root );
			return array( 'sha256' => $hash ? $hash : '', 'file_count' => $hash ? 1 : 0, 'complete' => (bool) $hash );
		}

		$root_real = realpath( $root );
		$files = array();
		$complete = (bool) $root_real;
		if ( ! $root_real ) {
			return array( 'sha256' => '', 'file_count' => 0, 'complete' => false );
		}
		try {
			$iterator = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $root_real, FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::LEAVES_ONLY );
			foreach ( $iterator as $file ) {
				if ( $file->isLink() ) {
					$complete = false;
					continue;
				}
				if ( ! $file->isFile() ) {
					continue;
				}
				$path = $file->getPathname();
				$real = realpath( $path );
				if ( ! $real || 0 !== strpos( wp_normalize_path( $real ), trailingslashit( wp_normalize_path( $root_real ) ) ) ) {
					$complete = false;
					continue;
				}
				$hash = @hash_file( 'sha256', $real );
				if ( false === $hash ) {
					$complete = false;
					continue;
				}
				$relative = ltrim( wp_normalize_path( str_replace( $root_real, '', $real ) ), '/' );
				$files[ $relative ] = $hash . '|' . (string) filesize( $real );
			}
		} catch ( UnexpectedValueException $e ) {
			$complete = false;
		}
		ksort( $files, SORT_STRING );
		$rows = array();
		foreach ( $files as $relative => $fingerprint ) {
			$rows[] = $relative . '|' . $fingerprint;
		}
		return array(
			'sha256' => $files ? hash( 'sha256', implode( "\n", $rows ) ) : '',
			'file_count' => count( $files ),
			'complete' => $complete && ! empty( $files ),
		);
	}

	public static function is_plugin_approved( $plugin_file ) {
		$inventory = self::plugin_inventory();
		return ! empty( $inventory[ $plugin_file ]['approved'] );
	}

	public static function approval_drift() {
		$drift = array();
		foreach ( self::plugin_inventory() as $plugin ) {
			if ( $plugin['active'] && ! $plugin['approved'] ) {
				$drift[] = $plugin;
			}
		}
		return $drift;
	}

	public static function health( $settings, $results ) {
		$issues = array();
		$guard = AIO_PS_Plugin::guard_status();
		if ( empty( $guard['verified'] ) ) {
			$issues[] = array( 'severity' => 'critical', 'code' => 'mu_guard_missing', 'message' => __( 'The AIO early-boot MU guard is missing or has been modified.', 'aio-sentinel' ) );
		}
		$next_scan = wp_next_scheduled( AIO_PS_Plugin::CRON_HOOK );
		if ( ! $next_scan ) {
			$issues[] = array( 'severity' => 'critical', 'code' => 'scan_unscheduled', 'message' => __( 'The scheduled AIO Sentinel scan is not registered.', 'aio-sentinel' ) );
		}
		if ( defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON ) {
			$issues[] = array( 'severity' => 'warning', 'code' => 'wp_cron_disabled', 'message' => __( 'WP-Cron is disabled. Confirm that the host scheduler calls wp-cron.php.', 'aio-sentinel' ) );
		}
		$last_scan = isset( $results['scanned_at'] ) ? strtotime( $results['scanned_at'] . ' UTC' ) : false;
		$interval = self::interval_seconds( isset( $settings['scan_interval'] ) ? $settings['scan_interval'] : 'hourly' );
		if ( ! $last_scan ) {
			$issues[] = array( 'severity' => 'warning', 'code' => 'scan_never_completed', 'message' => __( 'No AIO Sentinel scan has completed yet.', 'aio-sentinel' ) );
		} elseif ( time() - $last_scan > max( 900, $interval * 3 ) ) {
			$issues[] = array( 'severity' => 'warning', 'code' => 'scan_stale', 'message' => __( 'The last completed scan is older than expected. Check traffic and the host cron scheduler.', 'aio-sentinel' ) );
		}
		if ( ! empty( $settings['enforce_plugin_approval'] ) ) {
			$drift = self::approval_drift();
			if ( ! empty( $drift ) ) {
				/* translators: %d: number of active plugins outside the approved inventory. */
				$issues[] = array( 'severity' => 'warning', 'code' => 'plugin_approval_drift', 'message' => sprintf( _n( '%d active plugin is not in the approved inventory.', '%d active plugins are not in the approved inventory.', count( $drift ), 'aio-sentinel' ), count( $drift ) ) );
			}
		}
		$status = array( 'checked_at' => current_time( 'mysql', true ), 'next_scan' => $next_scan ? gmdate( 'Y-m-d H:i:s', $next_scan ) : '', 'issues' => $issues );
		update_option( self::OPTION_HEALTH, $status, false );
		return $status;
	}

	public static function latest_health() {
		return get_option( self::OPTION_HEALTH, array( 'checked_at' => '', 'next_scan' => '', 'issues' => array() ) );
	}

	public static function run_external_checks( $settings ) {
		if ( empty( $settings['external_monitor'] ) ) {
			return get_option( self::OPTION_EXTERNAL, array( 'checked_at' => '', 'enabled' => false, 'checks' => array() ) );
		}
		$urls = array_merge( array( home_url( '/' ) ), self::custom_urls( isset( $settings['monitor_urls'] ) ? $settings['monitor_urls'] : '' ) );
		$urls = array_slice( array_values( array_unique( $urls ) ), 0, 12 );
		$checks = array();
		foreach ( $urls as $url ) {
			$response = wp_remote_get( $url, array( 'timeout' => 15, 'redirection' => 3, 'user-agent' => 'AIO-Plugin-Sentinel/' . AIO_PS_VERSION . '; ' . home_url( '/' ) ) );
			if ( is_wp_error( $response ) ) {
				$checks[] = array( 'url' => $url, 'status' => 0, 'error' => $response->get_error_message(), 'suspicious' => false, 'markers' => array() );
				continue;
			}
			$body = substr( (string) wp_remote_retrieve_body( $response ), 0, 524288 );
			$markers = self::fake_verification_markers( $body );
			$checks[] = array(
				'url' => $url,
				'status' => (int) wp_remote_retrieve_response_code( $response ),
				'error' => '',
				'suspicious' => count( $markers ) >= 4 && in_array( 'cloudflare', $markers, true ),
				'markers' => $markers,
			);
		}
		$results = array( 'checked_at' => current_time( 'mysql', true ), 'enabled' => true, 'checks' => $checks );
		update_option( self::OPTION_EXTERNAL, $results, false );
		return $results;
	}

	public static function latest_external() {
		return get_option( self::OPTION_EXTERNAL, array( 'checked_at' => '', 'enabled' => false, 'checks' => array() ) );
	}

	/**
	 * Uses WordPress' existing update data. Availability is not the same as a
	 * vulnerability verdict, so the dashboard deliberately labels it as exposure.
	 */
	public static function update_exposure() {
		$plugin_updates = get_site_transient( 'update_plugins' );
		$plugin_updates = is_object( $plugin_updates ) && isset( $plugin_updates->response ) && is_array( $plugin_updates->response ) ? $plugin_updates->response : array();
		$core_updates = get_site_transient( 'update_core' );
		$core_updates = is_object( $core_updates ) && isset( $core_updates->updates ) && is_array( $core_updates->updates ) ? $core_updates->updates : array();
		$core_available = false;
		foreach ( $core_updates as $update ) {
			if ( isset( $update->response ) && 'upgrade' === $update->response ) {
				$core_available = true;
				break;
			}
		}
		return array( 'core_update_available' => $core_available, 'plugin_updates' => array_keys( $plugin_updates ), 'checked_at' => current_time( 'mysql', true ) );
	}

	public static function suspicious_external_checks( $external ) {
		return array_values( array_filter( isset( $external['checks'] ) ? $external['checks'] : array(), function( $check ) {
			return ! empty( $check['suspicious'] );
		} ) );
	}

	public static function sanitize_monitor_urls( $raw ) {
		return implode( "\n", self::custom_urls( sanitize_textarea_field( $raw ) ) );
	}

	private static function custom_urls( $raw ) {
		$urls = array();
		$home_host = strtolower( (string) wp_parse_url( home_url( '/' ), PHP_URL_HOST ) );
		foreach ( preg_split( '/[\r\n,\s]+/', (string) $raw ) as $url ) {
			$url = esc_url_raw( trim( $url ) );
			$host = strtolower( (string) wp_parse_url( $url, PHP_URL_HOST ) );
			if ( $url && $home_host && $host === $home_host && in_array( wp_parse_url( $url, PHP_URL_SCHEME ), array( 'http', 'https' ), true ) ) {
				$urls[] = $url;
			}
		}
		return $urls;
	}

	private static function fake_verification_markers( $body ) {
		$body = strtolower( wp_strip_all_tags( (string) $body ) );
		$markers = array();
		foreach ( array( 'cloudflare', 'additional verification required', 'press r', 'press v', 'press enter', 'ctrl' ) as $marker ) {
			if ( false !== strpos( $body, $marker ) ) {
				$markers[] = $marker;
			}
		}
		return $markers;
	}

	private static function interval_seconds( $interval ) {
		$intervals = array( 'aio_ps_15_minutes' => 15 * MINUTE_IN_SECONDS, 'hourly' => HOUR_IN_SECONDS, 'twicedaily' => 12 * HOUR_IN_SECONDS, 'daily' => DAY_IN_SECONDS );
		return isset( $intervals[ $interval ] ) ? $intervals[ $interval ] : HOUR_IN_SECONDS;
	}
}
