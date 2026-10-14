<?php

defined( 'ABSPATH' ) || exit;

class AIO_PS_Scanner {

	const OPTION_RESULTS  = 'aio_ps_scan_results';
	const OPTION_BASELINE = 'aio_ps_integrity_baseline';

	private $blocked_slugs = array(
		'xdav-tracker', 'xdav-trackerd', 'google-api-updates', 'responsive-block-suite', 'suspicious-plugin-cleaner', 'block-lab-pro',
	);

	private $deception_markers = array(
		'xdav tracker', 'xdav-tracker', 'additional verification required', 'hold the windows key and press r', 'hold the windows key and press', 'cloudflare verification', 'performing security verification',
	);

	private $obfuscation_markers = array(
		'base64_decode(', 'gzinflate(', 'gzuncompress(', 'str_rot13(', 'fromcharcode(', 'rawurldecode(',
	);

	private $execution_markers = array(
		'eval(', 'assert(', 'create_function(', 'preg_replace(', '$_post', '$_request', '$_cookie',
	);

	public function scan() {
		$findings = array();
		$manifest = array();
		$reported_exact_slugs = array();
		foreach ( $this->scan_files() as $item ) {
			$fingerprint = $this->fingerprint_file( $item['path'] );
			if ( ! $fingerprint ) {
				continue;
			}
			$manifest[ $item['id'] ] = $fingerprint;
			$finding = $this->inspect_file( $item );
			if ( $finding ) {
				// A blocked plugin directory is quarantined as a unit, so report it once.
				if ( ! empty( $finding['exact_slug'] ) && isset( $reported_exact_slugs[ $finding['owner'] ] ) ) {
					continue;
				}
				if ( ! empty( $finding['exact_slug'] ) ) {
					$reported_exact_slugs[ $finding['owner'] ] = true;
				}
				$findings[] = $finding;
			}
		}
		$payload = array(
			'scanned_at' => current_time( 'mysql', true ),
			'findings'   => $findings,
			'integrity'  => $this->compare_baseline( $manifest ),
			'file_count' => count( $manifest ),
		);
		update_option( self::OPTION_RESULTS, $payload, false );
		return $payload;
	}

	public function latest_results() {
		return get_option( self::OPTION_RESULTS, array( 'scanned_at' => null, 'findings' => array(), 'integrity' => array(), 'file_count' => 0 ) );
	}

	public function create_baseline() {
		$results = $this->scan();
		foreach ( $results['findings'] as $finding ) {
			if ( 'critical' === $finding['severity'] ) {
				return new WP_Error( 'aio_ps_critical_findings', __( 'Baseline was not created because critical findings need review first.', 'aio-plugin-sentinel' ) );
			}
		}
		$manifest = array();
		foreach ( $this->scan_files() as $item ) {
			$fingerprint = $this->fingerprint_file( $item['path'] );
			if ( $fingerprint ) {
				$manifest[ $item['id'] ] = $fingerprint;
			}
		}
		$created_at = current_time( 'mysql', true );
		update_option( self::OPTION_BASELINE, array( 'created_at' => $created_at, 'files' => $manifest ), false );

		// The scan used to create a baseline happens before the baseline is saved.
		// Mark that just-created baseline as clean in the dashboard immediately.
		$results['integrity'] = array(
			'available'  => true,
			'created_at' => $created_at,
			'added'      => array(),
			'modified'   => array(),
			'removed'    => array(),
		);
		update_option( self::OPTION_RESULTS, $results, false );
		return true;
	}

	public function baseline() {
		return get_option( self::OPTION_BASELINE, array() );
	}

	public function is_blocked_slug( $slug ) {
		return in_array( strtolower( trim( $slug ) ), $this->blocked_slugs, true );
	}

	public function is_plugin_file_blocked( $plugin_file ) {
		$parts = explode( '/', ltrim( (string) $plugin_file, '/' ) );
		if ( empty( $parts[0] ) ) {
			return false;
		}
		$slug = count( $parts ) > 1 ? $parts[0] : pathinfo( $parts[0], PATHINFO_FILENAME );
		return $this->is_blocked_slug( $slug );
	}

	/**
	 * Freshly scans and removes only critical findings from active locations.
	 * Files are moved to the protected quarantine folder, never permanently deleted.
	 */
	public function quarantine_confirmed_findings( $known_slug_only = false ) {
		$results = $this->scan();
		$actions = array();
		$errors = array();
		$handled_plugins = array();
		$quarantined_plugins = array();
		$quarantined_files = array();
		foreach ( $results['findings'] as $finding ) {
			if ( 'critical' !== $finding['severity'] || ( $known_slug_only && empty( $finding['exact_slug'] ) ) ) {
				continue;
			}
			if ( 'plugin' === $finding['location'] && isset( $handled_plugins[ $finding['owner'] ] ) ) {
				continue;
			}
			$result = $this->quarantine_finding( $finding );
			if ( is_wp_error( $result ) ) {
				$errors[] = $finding['file'] . ': ' . $result->get_error_message();
			} elseif ( $result ) {
				$actions[] = $finding['file'];
				if ( 'plugin' === $finding['location'] ) {
					$quarantined_plugins[ $finding['owner'] ] = true;
				} else {
					$quarantined_files[ $finding['file'] ] = true;
				}
			}
			if ( 'plugin' === $finding['location'] ) {
				$handled_plugins[ $finding['owner'] ] = true;
			}
		}
		if ( ! empty( $actions ) ) {
			$results['findings'] = array_values( array_filter( $results['findings'], function( $finding ) use ( $quarantined_plugins, $quarantined_files ) {
				return ! ( ( 'plugin' === $finding['location'] && isset( $quarantined_plugins[ $finding['owner'] ] ) ) || isset( $quarantined_files[ $finding['file'] ] ) );
			} ) );
			$results['scanned_at'] = current_time( 'mysql', true );
			update_option( self::OPTION_RESULTS, $results, false );
		}

		return array( 'scan' => $results, 'actions' => array_values( array_unique( $actions ) ), 'errors' => $errors );
	}

	private function scan_files() {
		$items = array();
		$single_file_plugins = glob( WP_PLUGIN_DIR . '/*.php' );
		foreach ( is_array( $single_file_plugins ) ? $single_file_plugins : array() as $file ) {
			$items[] = $this->file_item( $file, 'plugin', pathinfo( $file, PATHINFO_FILENAME ) );
		}
		$plugin_dirs = glob( WP_PLUGIN_DIR . '/*', GLOB_ONLYDIR );
		foreach ( is_array( $plugin_dirs ) ? $plugin_dirs : array() as $directory ) {
			if ( defined( 'AIO_PS_DIR' ) && realpath( $directory ) === realpath( AIO_PS_DIR ) ) {
				continue;
			}
			$slug = basename( $directory );
			foreach ( $this->code_files( $directory ) as $file ) {
				$items[] = $this->file_item( $file, 'plugin', $slug );
			}
		}

		if ( defined( 'WPMU_PLUGIN_DIR' ) && is_dir( WPMU_PLUGIN_DIR ) ) {
			foreach ( $this->code_files( WPMU_PLUGIN_DIR ) as $file ) {
				if ( 'aio-plugin-sentinel-guard.php' === basename( $file ) && defined( 'AIO_PS_GUARD_SHA256' ) && hash_equals( AIO_PS_GUARD_SHA256, strtoupper( (string) @hash_file( 'sha256', $file ) ) ) ) {
					continue;
				}
				$items[] = $this->file_item( $file, 'mu-plugin', basename( $file ) );
			}
		}
		foreach ( array( 'advanced-cache.php', 'db.php', 'object-cache.php', 'sunrise.php', 'maintenance.php' ) as $dropin ) {
			$file = WP_CONTENT_DIR . '/' . $dropin;
			if ( is_file( $file ) ) {
				$items[] = $this->file_item( $file, 'drop-in', $dropin );
			}
		}

		$uploads = wp_get_upload_dir();
		if ( ! empty( $uploads['basedir'] ) && is_dir( $uploads['basedir'] ) ) {
			foreach ( $this->code_files( $uploads['basedir'], true, 250 ) as $file ) {
				$items[] = $this->file_item( $file, 'uploads', basename( $file ) );
			}
		}
		return $items;
	}

	private function file_item( $path, $location, $owner ) {
		$relative = wp_normalize_path( str_replace( ABSPATH, '', $path ) );
		return array( 'id' => $location . ':' . $relative, 'path' => $path, 'relative' => $relative, 'location' => $location, 'owner' => $owner );
	}

	private function inspect_file( $item ) {
		$content = @file_get_contents( $item['path'], false, null, 0, 1048576 );
		if ( false === $content ) {
			return null;
		}
		$lower = strtolower( $content );
		$deception = $this->matching_markers( $lower, $this->deception_markers );
		$obfuscation = $this->matching_markers( $lower, $this->obfuscation_markers );
		$execution = $this->matching_markers( $lower, $this->execution_markers );
		$exact_slug = 'plugin' === $item['location'] && $this->is_blocked_slug( $item['owner'] );
		$score = $exact_slug || ! empty( $deception ) ? 100 : 0;
		if ( count( $obfuscation ) >= 2 ) {
			$score += 25;
		}
		if ( ! empty( $obfuscation ) && array_intersect( array( 'eval(', 'assert(', 'create_function(' ), $execution ) ) {
			$score += 50;
		}
		if ( 'uploads' === $item['location'] ) {
			$score += 40;
		}
		if ( $score < 50 ) {
			return null;
		}
		return array(
			'id' => $item['id'], 'location' => $item['location'], 'owner' => $item['owner'], 'file' => $item['relative'],
			'severity' => $score >= 100 ? 'critical' : 'review', 'exact_slug' => $exact_slug,
			'markers' => array_merge( $deception, $obfuscation, $execution ),
		);
	}

	private function quarantine_finding( $finding ) {
		$source = ABSPATH . ltrim( $finding['file'], '/\\' );
		if ( 'plugin' === $finding['location'] ) {
			$directory = WP_PLUGIN_DIR . '/' . $finding['owner'];
			if ( is_dir( $directory ) ) {
				$source = $directory;
			}
		}
		if ( ! file_exists( $source ) || ! $this->is_allowed_source( $source, $finding['location'] ) ) {
			return new WP_Error( 'aio_ps_invalid_source', __( 'The finding is no longer in a permitted active location.', 'aio-plugin-sentinel' ) );
		}
		$quarantine = WP_CONTENT_DIR . '/aio-plugin-sentinel-quarantine';
		if ( ! wp_mkdir_p( $quarantine ) ) {
			return new WP_Error( 'aio_ps_quarantine_unavailable', __( 'Could not create the quarantine directory.', 'aio-plugin-sentinel' ) );
		}
		$this->protect_quarantine( $quarantine );
		$destination = $quarantine . '/' . gmdate( 'Ymd-His' ) . '-' . sanitize_file_name( basename( $source ) );
		if ( ! @rename( $source, $destination ) ) {
			return new WP_Error( 'aio_ps_quarantine_failed', __( 'Could not move the finding to quarantine. Check file permissions.', 'aio-plugin-sentinel' ) );
		}
		if ( 'plugin' === $finding['location'] ) {
			$this->deactivate_plugin_owner( $finding['owner'] );
		}
		$this->write_quarantine_log( $finding, $source, $destination );
		return true;
	}

	/**
	 * Returns recent quarantine moves. Legacy entries lack an exact source path and
	 * are intentionally not offered for restoration.
	 */
	public function quarantine_entries() {
		$log = WP_CONTENT_DIR . '/aio-plugin-sentinel-quarantine/manifest.log';
		if ( ! is_readable( $log ) ) {
			return array();
		}
		$entries = array();
		$lines = @file( $log, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES );
		if ( ! is_array( $lines ) ) {
			return array();
		}
		$lines = array_reverse( array_filter( $lines ) );
		foreach ( array_slice( $lines, 0, 50 ) as $line ) {
			$entry = json_decode( $line, true );
			if ( is_array( $entry ) && ! empty( $entry['source_path'] ) && ! empty( $entry['destination'] ) ) {
				$entry['token'] = hash( 'sha256', $entry['source_path'] . '|' . $entry['destination'] );
				$entries[] = $entry;
			}
		}
		return $entries;
	}

	/**
	 * Restores a selected item only when it still lives in the protected
	 * quarantine folder and its original active location is empty. It never activates a plugin.
	 */
	public function restore_quarantined( $token ) {
		foreach ( $this->quarantine_entries() as $entry ) {
			if ( hash_equals( $entry['token'], (string) $token ) ) {
				$source = ABSPATH . ltrim( $entry['source_path'], '/\\' );
				$destination = ABSPATH . ltrim( $entry['destination'], '/\\' );
				$quarantine = WP_CONTENT_DIR . '/aio-plugin-sentinel-quarantine';
				if ( ! file_exists( $destination ) ) {
					return new WP_Error( 'aio_ps_restore_missing', __( 'The quarantined item is no longer available.', 'aio-plugin-sentinel' ) );
				}
				if ( ! $this->is_safe_restore_path( $source ) || ! $this->is_path_in_root( $destination, $quarantine ) ) {
					return new WP_Error( 'aio_ps_restore_invalid', __( 'The requested restore item is outside the permitted quarantine paths.', 'aio-plugin-sentinel' ) );
				}
				if ( file_exists( $source ) ) {
					return new WP_Error( 'aio_ps_restore_exists', __( 'The original location is already occupied, so nothing was restored.', 'aio-plugin-sentinel' ) );
				}
				if ( ! wp_mkdir_p( dirname( $source ) ) || ! @rename( $destination, $source ) ) {
					return new WP_Error( 'aio_ps_restore_failed', __( 'WordPress could not restore the quarantined item. Check hosting file permissions.', 'aio-plugin-sentinel' ) );
				}
				return true;
			}
		}
		return new WP_Error( 'aio_ps_restore_unknown', __( 'The requested quarantine record could not be found.', 'aio-plugin-sentinel' ) );
	}

	private function is_allowed_source( $source, $location ) {
		$roots = array(
			'plugin' => WP_PLUGIN_DIR,
			'mu-plugin' => defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : '',
			'drop-in' => WP_CONTENT_DIR,
			'uploads' => wp_get_upload_dir()['basedir'],
		);
		return ! empty( $roots[ $location ] ) && $this->is_path_in_root( $source, $roots[ $location ] );
	}

	private function is_path_in_root( $path, $root ) {
		$real_path = realpath( $path );
		$real_root = realpath( $root );
		return $real_path && $real_root && ( $real_path === $real_root || 0 === strpos( $real_path, trailingslashit( $real_root ) ) );
	}

	private function is_safe_restore_path( $path ) {
		$path = wp_normalize_path( $path );
		foreach ( array( WP_PLUGIN_DIR, defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : '', wp_get_upload_dir()['basedir'] ) as $root ) {
			$root = wp_normalize_path( $root );
			if ( $root && 0 === strpos( $path, trailingslashit( $root ) ) ) {
				return true;
			}
		}
		$allowed_dropins = array( 'advanced-cache.php', 'db.php', 'object-cache.php', 'sunrise.php', 'maintenance.php' );
		return wp_normalize_path( dirname( $path ) ) === wp_normalize_path( WP_CONTENT_DIR ) && in_array( basename( $path ), $allowed_dropins, true );
	}

	private function matching_markers( $content, $markers ) {
		return array_values( array_filter( $markers, function( $marker ) use ( $content ) {
			return false !== strpos( $content, $marker );
		} ) );
	}

	private function compare_baseline( $current ) {
		$baseline = $this->baseline();
		if ( empty( $baseline['files'] ) ) {
			return array( 'available' => false, 'added' => array(), 'modified' => array(), 'removed' => array() );
		}
		$previous = $baseline['files'];
		$added = array_values( array_diff_key( $current, $previous ) );
		$removed = array_keys( array_diff_key( $previous, $current ) );
		$modified = array();
		foreach ( array_intersect_key( $current, $previous ) as $id => $fingerprint ) {
			if ( $fingerprint['sha256'] !== $previous[ $id ]['sha256'] ) {
				$modified[] = $fingerprint;
			}
		}
		return array( 'available' => true, 'created_at' => $baseline['created_at'], 'added' => $added, 'modified' => $modified, 'removed' => $removed );
	}

	private function fingerprint_file( $path ) {
		$hash = @hash_file( 'sha256', $path );
		if ( false === $hash ) {
			return false;
		}
		return array( 'path' => wp_normalize_path( str_replace( ABSPATH, '', $path ) ), 'sha256' => $hash, 'size' => (int) filesize( $path ) );
	}

	private function code_files( $directory, $alternate_extensions = false, $limit = 0 ) {
		$files = array();
		$extensions = $alternate_extensions ? array( 'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phar' ) : array( 'php' );
		try {
			$iterator = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $directory, FilesystemIterator::SKIP_DOTS ) );
			foreach ( $iterator as $file ) {
				if ( $file->isFile() && in_array( strtolower( $file->getExtension() ), $extensions, true ) ) {
					$files[] = $file->getPathname();
					if ( $limit && count( $files ) >= $limit ) {
						break;
					}
				}
			}
		} catch ( UnexpectedValueException $e ) {
			return array();
		}
		return $files;
	}

	private function deactivate_plugin_owner( $owner ) {
		$active = (array) get_option( 'active_plugins', array() );
		$active = array_values( array_filter( $active, function( $plugin ) use ( $owner ) {
			return $plugin !== $owner . '.php' && 0 !== strpos( $plugin, $owner . '/' );
		} ) );
		update_option( 'active_plugins', $active );
	}

	private function protect_quarantine( $directory ) {
		if ( ! file_exists( $directory . '/index.php' ) ) {
			@file_put_contents( $directory . '/index.php', "<?php // Silence is golden.\n" );
		}
		if ( ! file_exists( $directory . '/.htaccess' ) ) {
			@file_put_contents( $directory . '/.htaccess', "Require all denied\nDeny from all\n" );
		}
		if ( ! file_exists( $directory . '/web.config' ) ) {
			@file_put_contents( $directory . '/web.config', '<?xml version="1.0"?><configuration><system.webServer><authorization><deny users="*" /></authorization></system.webServer></configuration>' );
		}
	}

	private function write_quarantine_log( $finding, $source, $destination ) {
		$entry = array( 'time' => current_time( 'mysql', true ), 'source' => $finding['file'], 'source_path' => wp_normalize_path( str_replace( ABSPATH, '', $source ) ), 'destination' => wp_normalize_path( str_replace( ABSPATH, '', $destination ) ) );
		@file_put_contents( WP_CONTENT_DIR . '/aio-plugin-sentinel-quarantine/manifest.log', wp_json_encode( $entry ) . "\n", FILE_APPEND | LOCK_EX );
	}
}
