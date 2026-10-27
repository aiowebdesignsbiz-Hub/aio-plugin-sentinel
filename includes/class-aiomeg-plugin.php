<?php

defined( 'ABSPATH' ) || exit;

class AIOMEG_Plugin {

	const CRON_HOOK = 'aiomeg_scheduled_scan';
	const OPTION_SETTINGS = 'aiomeg_settings';
	const OPTION_ALERT = 'aiomeg_last_alert_fingerprint';
	const OPTION_CLEANUP_LOG = 'aiomeg_cleanup_log';
	const OPTION_GUARD_STATUS = 'aiomeg_mu_guard_status';
	const GUARD_FILENAME = 'aio-plugin-sentinel-guard.php';
	const LEGACY_CRON_HOOK = 'aio_ps_scheduled_scan';
	private static $instance;
	private $scanner;

	public static function instance() {
		if ( ! self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	public static function activate() {
		self::migrate_legacy_data();
		// Updates and reactivations add new defaults without overwriting site choices.
		self::migrate_settings();
		self::install_mu_guard();
		self::reschedule_scans();
	}

	public static function deactivate() {
		wp_clear_scheduled_hook( self::CRON_HOOK );
	}

	private function __construct() {
		$this->scanner = new AIOMEG_Scanner();
		add_filter( 'cron_schedules', array( $this, 'add_cron_schedules' ) );
		add_action( 'admin_menu', array( $this, 'register_menu' ) );
		add_action( 'admin_post_aiomeg_scan', array( $this, 'handle_scan' ) );
		add_action( 'wp_ajax_aiomeg_run_scan', array( $this, 'handle_ajax_scan' ) );
		add_action( 'admin_post_aiomeg_baseline', array( $this, 'handle_baseline' ) );
		add_action( 'admin_post_aiomeg_cleanup', array( $this, 'handle_cleanup' ) );
		add_action( 'admin_post_aiomeg_settings', array( $this, 'handle_settings' ) );
		add_action( 'admin_post_aiomeg_test_email', array( $this, 'handle_test_email' ) );
		add_action( 'admin_post_aiomeg_install_guard', array( $this, 'handle_install_guard' ) );
		add_action( 'admin_post_aiomeg_download_guard', array( $this, 'handle_download_guard' ) );
		add_action( 'admin_post_aiomeg_approve_inventory', array( $this, 'handle_approve_inventory' ) );
		add_action( 'admin_post_aiomeg_revoke_inventory', array( $this, 'handle_revoke_inventory' ) );
		add_action( 'admin_post_aiomeg_export_evidence', array( $this, 'handle_export_evidence' ) );
		add_action( 'admin_post_aiomeg_restore_quarantine', array( $this, 'handle_restore_quarantine' ) );
		add_action( self::CRON_HOOK, array( $this, 'run_scheduled_scan' ) );
		add_action( 'plugins_loaded', array( __CLASS__, 'maybe_install_mu_guard' ), 20 );
		add_action( 'admin_init', array( $this, 'record_health' ) );
		add_action( 'admin_init', array( $this, 'prevent_admin_caching' ) );
		add_action( 'admin_init', array( $this, 'add_privacy_policy_content' ) );
		add_filter( 'pre_update_option_active_plugins', array( $this, 'block_activation' ), 10, 3 );
		add_filter( 'upgrader_pre_install', array( $this, 'check_upgrade_source' ), 10, 2 );
		add_action( 'upgrader_process_complete', array( $this, 'run_post_update_scan' ), 20 );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_assets' ) );
	}

	/**
	 * Preserve existing values and only add defaults introduced by a newer release.
	 */
	private static function migrate_settings() {
		$stored = get_option( self::OPTION_SETTINGS, null );
		if ( null === $stored || false === $stored ) {
			update_option( self::OPTION_SETTINGS, self::default_settings(), false );
			return;
		}

		if ( is_array( $stored ) ) {
			$merged = wp_parse_args( $stored, self::default_settings() );
			if ( $merged !== $stored ) {
				update_option( self::OPTION_SETTINGS, $merged, false );
			}
		}
	}

	/**
	 * Import pre-directory-release records once, retaining the source records so a
	 * site can safely roll back while its administrator verifies the new release.
	 */
	private static function migrate_legacy_data() {
		$legacy_options = array(
			'aio_ps_settings'                 => self::OPTION_SETTINGS,
			'aio_ps_last_alert_fingerprint'   => self::OPTION_ALERT,
			'aio_ps_cleanup_log'              => self::OPTION_CLEANUP_LOG,
			'aio_ps_mu_guard_status'          => self::OPTION_GUARD_STATUS,
			'aio_ps_scan_results'             => AIOMEG_Scanner::OPTION_RESULTS,
			'aio_ps_integrity_baseline'       => AIOMEG_Scanner::OPTION_BASELINE,
			'aio_ps_plugin_approvals'         => AIOMEG_Monitor::OPTION_APPROVALS,
			'aio_ps_health_status'            => AIOMEG_Monitor::OPTION_HEALTH,
			'aio_ps_external_monitor_results' => AIOMEG_Monitor::OPTION_EXTERNAL,
		);

		foreach ( $legacy_options as $legacy_key => $current_key ) {
			if ( false !== get_option( $current_key, false ) ) {
				continue;
			}
			$legacy_value = get_option( $legacy_key, false );
			if ( false !== $legacy_value ) {
				update_option( $current_key, $legacy_value, false );
			}
		}

		$settings = get_option( self::OPTION_SETTINGS, array() );
		if ( is_array( $settings ) && isset( $settings['scan_interval'] ) && 'aio_ps_15_minutes' === $settings['scan_interval'] ) {
			$settings['scan_interval'] = 'aiomeg_15_minutes';
			update_option( self::OPTION_SETTINGS, $settings, false );
		}
		wp_clear_scheduled_hook( self::LEGACY_CRON_HOOK );
	}

	/**
	 * Resolve the standard plugins directory from this plugin's installed path.
	 * This works with custom content directories without depending on constants.
	 */
	public static function plugins_directory() {
		return dirname( untrailingslashit( AIOMEG_DIR ) );
	}

	public function enqueue_admin_assets( $hook_suffix ) {
		if ( 'tools_page_aio-malicious-extension-guard' !== $hook_suffix ) {
			return;
		}
		wp_enqueue_style( 'aio-malicious-extension-guard-admin', AIOMEG_URL . 'assets/admin.css', array(), AIOMEG_VERSION );
		wp_enqueue_script( 'aio-malicious-extension-guard-admin', AIOMEG_URL . 'assets/admin.js', array(), AIOMEG_VERSION, true );
		wp_localize_script(
			'aio-malicious-extension-guard-admin',
			'aiomegAdmin',
			array(
				'ajaxUrl' => admin_url( 'admin-ajax.php' ),
				'nonce'   => wp_create_nonce( 'aiomeg_ajax_scan' ),
			)
		);
	}

	public function add_cron_schedules( $schedules ) {
		$schedules['aiomeg_15_minutes'] = array( 'interval' => 15 * MINUTE_IN_SECONDS, 'display' => __( 'Every 15 Minutes (AIO Malicious Extension Guard)', 'aio-malicious-extension-guard' ) );
		return $schedules;
	}

	public static function reschedule_scans() {
		wp_clear_scheduled_hook( self::CRON_HOOK );
		$settings = wp_parse_args( get_option( self::OPTION_SETTINGS, array() ), self::default_settings() );
		$schedules = array( 'aiomeg_15_minutes', 'hourly', 'twicedaily', 'daily' );
		$recurrence = in_array( $settings['scan_interval'], $schedules, true ) ? $settings['scan_interval'] : 'hourly';
		wp_schedule_event( time() + MINUTE_IN_SECONDS, $recurrence, self::CRON_HOOK );
	}

	public static function default_settings() {
		return array(
			'change_lock' => false,
			'scan_interval' => 'hourly',
			'notification_recipients' => '',
			'auto_quarantine_known' => false,
			'approved_admins' => '',
			'cleanup_unapproved_admins' => false,
			'enforce_plugin_approval' => false,
			'external_monitor' => false,
			'monitor_urls' => '',
			'delete_data_on_uninstall' => false,
		);
	}

	/**
	 * Keep the standalone guard in sync after a AIO Malicious Extension Guard update without
	 * touching an unrelated file that happens to share its filename.
	 */
	public static function maybe_install_mu_guard() {
		$status = self::guard_status();
		if ( ! $status['verified'] && $status['source_available'] ) {
			self::install_mu_guard();
		}
	}

	public static function install_mu_guard() {
		$filesystem = self::filesystem();
		if ( ! $filesystem ) {
			return self::save_guard_status( array( 'state' => 'filesystem_unavailable', 'message' => __( 'WordPress could not initialize its filesystem service for the MU guard.', 'aio-malicious-extension-guard' ) ) );
		}
		$source = self::guard_source_path();
		if ( ! is_readable( $source ) ) {
			return self::save_guard_status( array( 'state' => 'source_unavailable', 'message' => __( 'The bundled MU guard file is unavailable.', 'aio-malicious-extension-guard' ) ) );
		}

		$directory = self::guard_directory();
		if ( ! is_dir( $directory ) && ! wp_mkdir_p( $directory ) ) {
			return self::save_guard_status( array( 'state' => 'directory_unavailable', 'message' => __( 'WordPress could not create wp-content/mu-plugins.', 'aio-malicious-extension-guard' ) ) );
		}
		if ( ! $filesystem->is_writable( $directory ) ) {
			return self::save_guard_status( array( 'state' => 'directory_not_writable', 'message' => __( 'wp-content/mu-plugins is not writable by WordPress. Download the guard and upload it through the host file manager.', 'aio-malicious-extension-guard' ) ) );
		}

		$target = trailingslashit( $directory ) . self::GUARD_FILENAME;
		$source_hash = hash_file( 'sha256', $source );
		$target_hash = is_file( $target ) ? hash_file( 'sha256', $target ) : false;
		if ( $target_hash && hash_equals( $source_hash, $target_hash ) ) {
			return self::save_guard_status( array( 'state' => 'verified', 'message' => __( 'The early-boot MU guard is installed and verified.', 'aio-malicious-extension-guard' ), 'hash' => $source_hash ) );
		}

		if ( is_file( $target ) && ! self::backup_existing_guard( $target ) ) {
			return self::save_guard_status( array( 'state' => 'backup_failed', 'message' => __( 'The existing MU guard could not be backed up, so it was not replaced.', 'aio-malicious-extension-guard' ) ) );
		}
		if ( ! $filesystem->copy( $source, $target, true, FS_CHMOD_FILE ) || ! is_file( $target ) || ! hash_equals( $source_hash, (string) hash_file( 'sha256', $target ) ) ) {
			return self::save_guard_status( array( 'state' => 'copy_failed', 'message' => __( 'WordPress could not install and verify the MU guard. Check hosting file permissions.', 'aio-malicious-extension-guard' ) ) );
		}

		return self::save_guard_status( array( 'state' => 'verified', 'message' => __( 'The early-boot MU guard is installed and verified.', 'aio-malicious-extension-guard' ), 'hash' => $source_hash ) );
	}

	public static function guard_status() {
		$source = self::guard_source_path();
		$target = trailingslashit( self::guard_directory() ) . self::GUARD_FILENAME;
		$source_available = is_readable( $source );
		$source_hash = $source_available ? hash_file( 'sha256', $source ) : false;
		$target_hash = is_file( $target ) ? hash_file( 'sha256', $target ) : false;
		return array(
			'source_available' => $source_available,
			'verified' => $source_hash && $target_hash && hash_equals( $source_hash, $target_hash ),
			'directory' => self::guard_directory(),
			'target' => $target,
			'last_attempt' => get_option( self::OPTION_GUARD_STATUS, array() ),
		);
	}

	private static function guard_source_path() {
		return AIOMEG_DIR . 'mu-plugin/' . self::GUARD_FILENAME;
	}

	private static function guard_directory() {
		return defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';
	}

	private static function backup_existing_guard( $target ) {
		$filesystem = self::filesystem();
		if ( ! $filesystem ) {
			return false;
		}
		$uploads = wp_get_upload_dir();
		$directory = trailingslashit( $uploads['basedir'] ) . 'aio-malicious-extension-guard-quarantine/mu-guard-backups';
		if ( ! wp_mkdir_p( $directory ) || ! self::protect_guard_backups( $directory ) ) {
			return false;
		}
		// A .txt extension ensures a backup cannot be executed if server rules are bypassed.
		$backup = trailingslashit( $directory ) . gmdate( 'Ymd-His' ) . '-' . self::GUARD_FILENAME . '.txt';
		return $filesystem->copy( $target, $backup, false, FS_CHMOD_FILE );
	}

	private static function protect_guard_backups( $directory ) {
		$filesystem = self::filesystem();
		if ( ! $filesystem ) {
			return false;
		}
		$files = array(
			'index.php' => "<?php // Silence is golden.\n",
			'.htaccess' => "Require all denied\nDeny from all\n",
			'web.config' => '<?xml version="1.0"?><configuration><system.webServer><authorization><deny users="*" /></authorization></system.webServer></configuration>',
		);
		foreach ( $files as $name => $contents ) {
			$file = trailingslashit( $directory ) . $name;
			if ( ! $filesystem->exists( $file ) && ! $filesystem->put_contents( $file, $contents, FS_CHMOD_FILE ) ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Initialize WordPress's filesystem abstraction so managed hosts can provide
	 * credentials or alternate transports without direct PHP file writes.
	 */
	private static function filesystem() {
		require_once ABSPATH . 'wp-admin/includes/file.php';
		global $wp_filesystem;
		if ( ! $wp_filesystem && ! WP_Filesystem() ) {
			return false;
		}
		return $wp_filesystem;
	}

	private static function save_guard_status( $status ) {
		$status['checked_at'] = current_time( 'mysql', true );
		update_option( self::OPTION_GUARD_STATUS, $status, false );
		return $status;
	}

	public function register_menu() {
		add_management_page( __( 'AIO Malicious Extension Guard', 'aio-malicious-extension-guard' ), __( 'AIO Malicious Extension Guard', 'aio-malicious-extension-guard' ), 'activate_plugins', 'aio-malicious-extension-guard', array( $this, 'render_page' ) );
	}

	/**
	 * Offer administrators accurate, ready-to-use disclosure text for the site's
	 * WordPress privacy-policy guide. The plugin has no telemetry by default.
	 */
	public function add_privacy_policy_content() {
		if ( ! function_exists( 'wp_add_privacy_policy_content' ) ) {
			return;
		}

		$content = '<p>' . esc_html__( 'AIO Malicious Extension Guard stores security-monitoring data locally in this WordPress installation. It does not send scan results, website files, WordPress user data, or credentials to AIO Web Designs or another third party.', 'aio-malicious-extension-guard' ) . '</p>';
		$content .= '<h2>' . esc_html__( 'Data collected and stored locally', 'aio-malicious-extension-guard' ) . '</h2>';
		$content .= '<p>' . esc_html__( 'The plugin records scan timestamps, findings, executable-file hashes, integrity baselines, approved-plugin fingerprints, configured notification-recipient email addresses, scan-health information, and cleanup audit records. These records are used only to operate the security monitoring and incident-response features on this site.', 'aio-malicious-extension-guard' ) . '</p>';
		$content .= '<h2>' . esc_html__( 'Network requests and email', 'aio-malicious-extension-guard' ) . '</h2>';
		$content .= '<p>' . esc_html__( 'Public-page monitoring is off by default. If an administrator enables it, the plugin requests only this site\'s homepage and administrator-supplied URLs on the same host to check for fake-verification patterns. It stores only the response status and matching indicator words, not the response body. Security notifications are sent through this site\'s configured WordPress mail system only to the site administrator and recipients an administrator enters.', 'aio-malicious-extension-guard' ) . '</p>';
		$content .= '<h2>' . esc_html__( 'Retention and deletion', 'aio-malicious-extension-guard' ) . '</h2>';
		$content .= '<p>' . esc_html__( 'Security records are retained when the plugin is uninstalled by default so incident evidence is not lost. An administrator can opt in to delete AIO Malicious Extension Guard settings, scan records, baselines, approvals, health data, and audit logs during uninstall. Quarantined files and the early-boot MU guard are never removed automatically and require deliberate host-level review.', 'aio-malicious-extension-guard' ) . '</p>';

		wp_add_privacy_policy_content( __( 'AIO Malicious Extension Guard', 'aio-malicious-extension-guard' ), wp_kses_post( $content ) );
	}

	public function handle_scan() {
		$this->require_admin_nonce( 'aiomeg_scan' );
		$this->run_monitoring_cycle();
		$this->redirect( array( 'aiomeg_notice' => 'scanned' ) );
	}

	/**
	 * Keeps the interactive scan responsive without claiming a made-up completion
	 * percentage. The browser displays an indeterminate progress state until the
	 * server has completed the same comprehensive scan used by scheduled checks.
	 */
	public function handle_ajax_scan() {
		if ( ! current_user_can( 'activate_plugins' ) ) {
			wp_send_json_error( array( 'message' => __( 'You are not allowed to run a security scan.', 'aio-malicious-extension-guard' ) ), 403 );
		}
		check_ajax_referer( 'aiomeg_ajax_scan', 'nonce' );
		$results = $this->run_monitoring_cycle();
		$critical = $this->critical_findings( $results );
		$review = array_values( array_filter( isset( $results['findings'] ) ? $results['findings'] : array(), function( $finding ) {
			return isset( $finding['severity'] ) && 'critical' !== $finding['severity'];
		} ) );
		wp_send_json_success(
			array(
				'criticalCount' => count( $critical ),
				'reviewCount'   => count( $review ),
				'fileCount'     => isset( $results['file_count'] ) ? absint( $results['file_count'] ) : 0,
				'findings'      => array_slice( array_map( function( $finding ) { return isset( $finding['file'] ) ? $finding['file'] : ''; }, $critical ), 0, 3 ),
			)
		);
	}

	/**
	 * Prevent a host or browser cache from serving an expired security token on this screen.
	 */
	public function prevent_admin_caching() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- This only controls response-cache headers.
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : '';
		if ( 'aio-malicious-extension-guard' !== $page ) {
			return;
		}

		nocache_headers();
	}

	public function handle_baseline() {
		$this->require_admin_nonce( 'aiomeg_baseline' );
		$result = $this->scanner->create_baseline();
		$this->redirect( is_wp_error( $result ) ? array( 'aiomeg_error' => rawurlencode( $result->get_error_message() ) ) : array( 'aiomeg_notice' => 'baseline' ) );
	}

	public function handle_cleanup() {
		$this->require_admin_nonce( 'aiomeg_cleanup' );
		if ( ! current_user_can( 'delete_plugins' ) || ! current_user_can( 'delete_users' ) ) {
			wp_die( esc_html__( 'You are not allowed to run incident cleanup.', 'aio-malicious-extension-guard' ) );
		}
		if ( empty( $_POST['aiomeg_acknowledge_cleanup'] ) ) {
			$this->redirect( array( 'aiomeg_error' => rawurlencode( __( 'Confirm the cleanup acknowledgment before quarantining critical findings.', 'aio-malicious-extension-guard' ) ) ) );
		}
		$cleanup = $this->scanner->quarantine_confirmed_findings();
		$removed_users = $this->remove_unapproved_administrators();
		$this->write_cleanup_log( $cleanup, $removed_users );
		set_transient( 'aiomeg_cleanup_feedback_' . get_current_user_id(), array( 'actions' => $cleanup['actions'], 'errors' => $cleanup['errors'], 'users' => $removed_users ), 5 * MINUTE_IN_SECONDS );
		$notice = empty( $cleanup['actions'] ) && empty( $removed_users ) ? 'nothing_to_clean' : 'cleaned';
		$this->redirect( array( 'aiomeg_notice' => $notice ) );
	}

	public function handle_settings() {
		if ( ! current_user_can( 'activate_plugins' ) ) {
			wp_die( esc_html__( 'You are not allowed to manage plugins.', 'aio-malicious-extension-guard' ) );
		}
		check_admin_referer( 'aiomeg_settings' );
		$intervals = array( 'aiomeg_15_minutes', 'hourly', 'twicedaily', 'daily' );
		$interval = isset( $_POST['scan_interval'] ) ? sanitize_key( wp_unslash( $_POST['scan_interval'] ) ) : 'hourly';
		$notification_recipients = isset( $_POST['notification_recipients'] ) ? sanitize_textarea_field( wp_unslash( $_POST['notification_recipients'] ) ) : '';
		$approved_admins = isset( $_POST['approved_admins'] ) ? sanitize_textarea_field( wp_unslash( $_POST['approved_admins'] ) ) : '';
		$monitor_urls = isset( $_POST['monitor_urls'] ) ? sanitize_textarea_field( wp_unslash( $_POST['monitor_urls'] ) ) : '';
		$settings = array(
			'change_lock' => ! empty( $_POST['change_lock'] ),
			'scan_interval' => in_array( $interval, $intervals, true ) ? $interval : 'hourly',
			'notification_recipients' => $this->sanitize_recipients( $notification_recipients ),
			'auto_quarantine_known' => ! empty( $_POST['auto_quarantine_known'] ),
			'approved_admins' => $this->sanitize_approved_admins( $approved_admins ),
			'cleanup_unapproved_admins' => ! empty( $_POST['cleanup_unapproved_admins'] ),
			'enforce_plugin_approval' => ! empty( $_POST['enforce_plugin_approval'] ),
			'external_monitor' => ! empty( $_POST['external_monitor'] ),
			'monitor_urls' => AIOMEG_Monitor::sanitize_monitor_urls( $monitor_urls ),
			'delete_data_on_uninstall' => ! empty( $_POST['delete_data_on_uninstall'] ),
		);
		update_option( self::OPTION_SETTINGS, $settings, false );
		self::reschedule_scans();
		$this->redirect( array( 'aiomeg_notice' => 'settings' ) );
	}

	public function handle_install_guard() {
		$this->require_admin_nonce( 'aiomeg_install_guard' );
		$status = self::install_mu_guard();
		$this->redirect( array( empty( $status['verified'] ) ? 'aiomeg_error' : 'aiomeg_notice' => rawurlencode( $status['message'] ) ) );
	}

	/**
	 * Send a harmless preview of the calm, no-infection notification design.
	 */
	public function handle_test_email() {
		$this->require_admin_nonce( 'aiomeg_test_email' );

		$sent = $this->send_notification(
			__( 'Test email: no infection found', 'aio-malicious-extension-guard' ),
			array(
				__( 'This is a test of the AIO Malicious Extension Guard security-notification email.', 'aio-malicious-extension-guard' ),
				__( 'No infection, reinfection, or required action is associated with this test.', 'aio-malicious-extension-guard' ),
			),
			'clear',
			current_time( 'mysql', true )
		);

		$this->redirect(
			array(
				$sent ? 'aiomeg_notice' : 'aiomeg_error' => $sent
					? 'test_email_sent'
					: rawurlencode( __( 'WordPress could not send the test email. Check the site mail configuration.', 'aio-malicious-extension-guard' ) ),
			)
		);
	}

	public function handle_download_guard() {
		$this->require_admin_nonce( 'aiomeg_download_guard' );
		$source = self::guard_source_path();
		$filesystem = self::filesystem();
		if ( ! $filesystem || ! $filesystem->exists( $source ) ) {
			wp_die( esc_html__( 'The bundled MU guard file is unavailable.', 'aio-malicious-extension-guard' ) );
		}
		$contents = $filesystem->get_contents( $source );
		if ( false === $contents ) {
			wp_die( esc_html__( 'WordPress could not read the bundled MU guard file.', 'aio-malicious-extension-guard' ) );
		}
		nocache_headers();
		header( 'Content-Type: application/octet-stream' );
		header( 'Content-Disposition: attachment; filename="' . self::GUARD_FILENAME . '"' );
		header( 'Content-Length: ' . (string) strlen( $contents ) );
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- This is a vetted bundled PHP file sent as an attachment.
		echo $contents;
		exit;
	}

	public function handle_approve_inventory() {
		if ( ! current_user_can( 'activate_plugins' ) ) {
			wp_die( esc_html__( 'You are not allowed to manage plugins.', 'aio-malicious-extension-guard' ) );
		}
		check_admin_referer( 'aiomeg_approve_inventory' );
		if ( empty( $_POST['aiomeg_acknowledge_inventory'] ) ) {
			$this->redirect( array( 'aiomeg_error' => rawurlencode( __( 'Confirm that you reviewed the full plugin directories before approving the inventory.', 'aio-malicious-extension-guard' ) ) ) );
		}
		$results = $this->scanner->scan();
		$critical = array_filter( $results['findings'], function( $finding ) {
			return isset( $finding['severity'] ) && 'critical' === $finding['severity'];
		} );
		if ( ! empty( $critical ) ) {
			$message = sprintf(
				/* translators: %d: number of critical findings. */
				_n( 'The inventory was not approved because the fresh scan found %d critical finding. Run Incident Cleanup or resolve the finding, then approve the reviewed plugins.', 'The inventory was not approved because the fresh scan found %d critical findings. Run Incident Cleanup or resolve the findings, then approve the reviewed plugins.', count( $critical ), 'aio-malicious-extension-guard' ),
				count( $critical )
			);
			$this->redirect( array( 'aiomeg_error' => rawurlencode( $message ), 'aiomeg_critical_count' => count( $critical ) ) );
		}
		$plugins = isset( $_POST['aiomeg_plugins'] ) ? array_map( 'sanitize_text_field', (array) wp_unslash( $_POST['aiomeg_plugins'] ) ) : array();
		$count = AIOMEG_Monitor::approve_plugins( $plugins );
		if ( ! $count ) {
			$this->redirect( array( 'aiomeg_error' => rawurlencode( __( 'Select at least one complete plugin directory to approve.', 'aio-malicious-extension-guard' ) ) ) );
		}
		$inventory = AIOMEG_Monitor::plugin_inventory();
		$persisted = 0;
		foreach ( array_unique( $plugins ) as $plugin_file ) {
			if ( ! empty( $inventory[ $plugin_file ]['approved'] ) ) {
				$persisted++;
			}
		}
		if ( $persisted !== $count ) {
			$this->redirect( array( 'aiomeg_error' => rawurlencode( __( 'The approval records could not be verified after saving. No approval success was reported; reload the page and try again.', 'aio-malicious-extension-guard' ) ) ) );
		}
		$this->redirect( array( 'aiomeg_notice' => 'inventory_approved', 'aiomeg_count' => $count ) );
	}

	public function handle_revoke_inventory() {
		if ( ! current_user_can( 'activate_plugins' ) ) {
			wp_die( esc_html__( 'You are not allowed to manage plugins.', 'aio-malicious-extension-guard' ) );
		}
		check_admin_referer( 'aiomeg_revoke_inventory' );
		$plugins = isset( $_POST['aiomeg_plugins'] ) ? array_map( 'sanitize_text_field', (array) wp_unslash( $_POST['aiomeg_plugins'] ) ) : array();
		$count = AIOMEG_Monitor::revoke_plugin_approvals( $plugins );
		if ( ! $count ) {
			$this->redirect( array( 'aiomeg_error' => rawurlencode( __( 'Select at least one previously approved plugin to revoke.', 'aio-malicious-extension-guard' ) ) ) );
		}
		$this->redirect( array( 'aiomeg_notice' => 'inventory_revoked', 'aiomeg_count' => $count ) );
	}

	public function handle_export_evidence() {
		$this->require_admin_nonce( 'aiomeg_export_evidence' );
		$report = array(
			'generated_at' => current_time( 'mysql', true ),
			'site_url' => home_url( '/' ),
			'plugin_version' => AIOMEG_VERSION,
			'latest_scan' => $this->scanner->latest_results(),
			'health' => AIOMEG_Monitor::latest_health(),
			'external_monitor' => AIOMEG_Monitor::latest_external(),
			'update_exposure' => AIOMEG_Monitor::update_exposure(),
			'plugin_inventory' => AIOMEG_Monitor::plugin_inventory(),
			'cleanup_audit_log' => get_option( self::OPTION_CLEANUP_LOG, array() ),
		);
		nocache_headers();
		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="aio-plugin-sentinel-evidence-' . gmdate( 'Ymd-His' ) . '.json"' );
		echo wp_json_encode( $report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES );
		exit;
	}

	public function handle_restore_quarantine() {
		if ( ! current_user_can( 'activate_plugins' ) ) {
			wp_die( esc_html__( 'You are not allowed to manage plugins.', 'aio-malicious-extension-guard' ) );
		}
		check_admin_referer( 'aiomeg_restore_quarantine' );
		if ( ! current_user_can( 'delete_plugins' ) ) {
			wp_die( esc_html__( 'You are not allowed to restore quarantined code.', 'aio-malicious-extension-guard' ) );
		}
		$token = isset( $_POST['aiomeg_quarantine_token'] ) ? sanitize_text_field( wp_unslash( $_POST['aiomeg_quarantine_token'] ) ) : '';
		$result = $this->scanner->restore_quarantined( $token );
		$this->redirect( is_wp_error( $result ) ? array( 'aiomeg_error' => rawurlencode( $result->get_error_message() ) ) : array( 'aiomeg_notice' => 'restored' ) );
	}

	public function run_scheduled_scan() {
		$results = $this->run_monitoring_cycle();
		$settings = $this->settings();
		if ( ! empty( $settings['auto_quarantine_known'] ) ) {
			$cleanup = $this->scanner->quarantine_confirmed_findings( true );
			if ( ! empty( $cleanup['actions'] ) || ! empty( $cleanup['errors'] ) ) {
				$this->write_cleanup_log( $cleanup, array() );
				$this->send_notification( __( 'Automatic containment completed', 'aio-malicious-extension-guard' ), array_merge( $cleanup['actions'], $cleanup['errors'] ), 'urgent', current_time( 'mysql', true ) );
			}
		}
	}

	public function run_post_update_scan() {
		$this->run_monitoring_cycle();
	}

	public function record_health() {
		if ( current_user_can( 'activate_plugins' ) ) {
			AIOMEG_Monitor::health( $this->settings(), $this->scanner->latest_results() );
		}
	}

	private function run_monitoring_cycle() {
		$results = $this->scanner->scan();
		$this->approve_sentinel_package();
		$external = AIOMEG_Monitor::run_external_checks( $this->settings() );
		$health = AIOMEG_Monitor::health( $this->settings(), $results );
		$this->notify_if_actionable( $results, $health, $external );
		return $results;
	}

	private function critical_findings( $results ) {
		return array_values( array_filter( isset( $results['findings'] ) ? $results['findings'] : array(), function( $finding ) {
			return isset( $finding['severity'] ) && 'critical' === $finding['severity'];
		} ) );
	}

	/**
	 * This plugin is the only plugin automatically recorded. All other installed
	 * plugins remain subject to the administrator's documented review decision.
	 */
	private function approve_sentinel_package() {
		$plugin_file = plugin_basename( AIOMEG_FILE );
		AIOMEG_Monitor::approve_plugins( array( $plugin_file ), __( 'AIO Malicious Extension Guard', 'aio-malicious-extension-guard' ) );
	}

	public function block_activation( $new_value, $old_value ) {
		$requested = array_diff( (array) $new_value, (array) $old_value );
		$settings = $this->settings();
		$blocked = array_filter( $requested, function( $plugin ) use ( $settings ) {
		if ( in_array( $plugin, array( 'aio-malicious-extension-guard/aio-malicious-extension-guard.php', 'aio-plugin-sentinel/aio-malicious-extension-guard.php', 'aio-plugin-sentinel/aio-plugin-sentinel.php' ), true ) ) {
				return false;
			}
			return $this->scanner->is_plugin_file_blocked( $plugin ) || ! empty( $settings['change_lock'] ) || ( ! empty( $settings['enforce_plugin_approval'] ) && ! AIOMEG_Monitor::is_plugin_approved( $plugin ) );
		} );
		if ( empty( $blocked ) ) {
			return $new_value;
		}
		foreach ( $blocked as $plugin ) {
			$key = array_search( $plugin, $new_value, true );
			if ( false !== $key ) {
				unset( $new_value[ $key ] );
			}
		}
		set_transient( 'aiomeg_activation_blocked', implode( ', ', $blocked ), MINUTE_IN_SECONDS );
		return array_values( $new_value );
	}

	public function check_upgrade_source( $response, $hook_extra ) {
		if ( empty( $hook_extra['plugin'] ) ) {
			return $response;
		}
		if ( $this->scanner->is_plugin_file_blocked( $hook_extra['plugin'] ) ) {
			return new WP_Error( 'aiomeg_upgrade_blocked', __( 'AIO Malicious Extension Guard blocked an update for a known malicious plugin identifier.', 'aio-malicious-extension-guard' ) );
		}
		if ( ! empty( $this->settings()['change_lock'] ) ) {
			return new WP_Error( 'aiomeg_lockdown_blocked', __( 'AIO Malicious Extension Guard change lock is enabled. Disable it temporarily to approve this plugin update.', 'aio-malicious-extension-guard' ) );
		}
		if ( ! empty( $this->settings()['enforce_plugin_approval'] ) && ! AIOMEG_Monitor::is_plugin_approved( $hook_extra['plugin'] ) ) {
			return new WP_Error( 'aiomeg_unapproved_upgrade', __( 'This plugin is not in the approved inventory. Review the plugin and capture the current inventory before updating it.', 'aio-malicious-extension-guard' ) );
		}
		return $response;
	}

	public function render_page() {
		if ( ! current_user_can( 'activate_plugins' ) ) {
			return;
		}
		$results = $this->scanner->latest_results();
		$baseline = $this->scanner->baseline();
		$settings = $this->settings();
		$health = AIOMEG_Monitor::health( $settings, $results );
		$external = AIOMEG_Monitor::latest_external();
		$inventory = AIOMEG_Monitor::plugin_inventory();
		$update_exposure = AIOMEG_Monitor::update_exposure();
		$has_initial_scan = ! empty( $results['scanned_at'] );
		?>
		<div class="wrap">
			<div class="aiomeg-brand">
				<a class="aiomeg-brand-logo" href="https://aiowebdesigns.com/" target="_blank" rel="noopener noreferrer">
					<img src="<?php echo esc_url( AIOMEG_URL . 'assets/aio-logo.png' ); ?>" alt="<?php esc_attr_e( 'AIO Web Designs', 'aio-malicious-extension-guard' ); ?>" />
				</a>
				<div>
					<h1><?php esc_html_e( 'AIO Malicious Extension Guard', 'aio-malicious-extension-guard' ); ?></h1>
					<p><?php esc_html_e( 'Scheduled detection and controlled incident response for plugins, must-use plugins, drop-ins, and executable uploads.', 'aio-malicious-extension-guard' ); ?></p>
					<p class="aiomeg-brand-link"><a href="https://aiowebdesigns.com/" target="_blank" rel="noopener noreferrer">aiowebdesigns.com</a></p>
				</div>
			</div>
			<p class="aiomeg-update-note"><?php esc_html_e( 'Plugin updates retain this site\'s monitoring settings, notification recipients, approved administrators, baseline, scan history, and cleanup audit log.', 'aio-malicious-extension-guard' ); ?></p>
			<?php $this->render_notices(); ?>
			<?php if ( ! $has_initial_scan ) : ?>
				<div class="aiomeg-initial-scan">
					<h2><?php esc_html_e( 'Start with a security scan', 'aio-malicious-extension-guard' ); ?></h2>
					<p><?php esc_html_e( 'Before any plugin can be trusted, AIO Malicious Extension Guard will inspect installed plugins, must-use plugins, drop-ins, and executable uploads for known critical indicators.', 'aio-malicious-extension-guard' ); ?></p>
					<?php $this->render_scan_button( true ); ?>
				</div>
			<?php else : ?>
				<?php $this->render_scan_button(); ?>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline-block"><input type="hidden" name="action" value="aiomeg_baseline" /><?php wp_nonce_field( 'aiomeg_baseline' ); ?><?php submit_button( empty( $baseline ) ? __( 'Create Clean Baseline', 'aio-malicious-extension-guard' ) : __( 'Refresh Baseline', 'aio-malicious-extension-guard' ), 'secondary', 'aiomeg_create_baseline', false ); ?></form>
			<?php endif; ?>
			<?php $this->render_health( $health, $external ); ?>
			<?php $this->render_update_exposure( $update_exposure ); ?>
			<h2><?php esc_html_e( 'Scheduled Monitoring & Notifications', 'aio-malicious-extension-guard' ); ?></h2>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="aiomeg_settings" /><?php wp_nonce_field( 'aiomeg_settings' ); ?>
				<table class="form-table" role="presentation"><tbody>
				<tr><th scope="row"><label for="aiomeg-interval"><?php esc_html_e( 'Scan interval', 'aio-malicious-extension-guard' ); ?></label></th><td><select id="aiomeg-interval" name="scan_interval"><option value="aiomeg_15_minutes" <?php selected( $settings['scan_interval'], 'aiomeg_15_minutes' ); ?>><?php esc_html_e( 'Every 15 minutes', 'aio-malicious-extension-guard' ); ?></option><option value="hourly" <?php selected( $settings['scan_interval'], 'hourly' ); ?>><?php esc_html_e( 'Hourly', 'aio-malicious-extension-guard' ); ?></option><option value="twicedaily" <?php selected( $settings['scan_interval'], 'twicedaily' ); ?>><?php esc_html_e( 'Twice daily', 'aio-malicious-extension-guard' ); ?></option><option value="daily" <?php selected( $settings['scan_interval'], 'daily' ); ?>><?php esc_html_e( 'Daily', 'aio-malicious-extension-guard' ); ?></option></select><p class="description"><?php esc_html_e( 'WP-Cron runs when WordPress receives traffic. Configure a host scheduler to call wp-cron.php for exact timing.', 'aio-malicious-extension-guard' ); ?></p></td></tr>
				<tr><th scope="row"><label for="aiomeg-recipients"><?php esc_html_e( 'Security notification emails', 'aio-malicious-extension-guard' ); ?></label></th><td><textarea id="aiomeg-recipients" name="notification_recipients" rows="4" class="large-text" placeholder="security@example.com, owner@example.com"><?php echo esc_textarea( $settings['notification_recipients'] ); ?></textarea><p class="description"><?php esc_html_e( 'Comma, space, or line-separated. The WordPress site administrator email is always included.', 'aio-malicious-extension-guard' ); ?></p></td></tr>
				<tr><th scope="row"><?php esc_html_e( 'Controls', 'aio-malicious-extension-guard' ); ?></th><td><label><input type="checkbox" name="change_lock" value="1" <?php checked( ! empty( $settings['change_lock'] ) ); ?> /> <?php esc_html_e( 'Lock all new plugin activation and plugin updates until explicitly approved.', 'aio-malicious-extension-guard' ); ?></label><br /><label><input type="checkbox" name="enforce_plugin_approval" value="1" <?php checked( ! empty( $settings['enforce_plugin_approval'] ) ); ?> /> <?php esc_html_e( 'Block activation of plugins not present in this site\'s approved-plugin inventory.', 'aio-malicious-extension-guard' ); ?></label><br /><label><input type="checkbox" name="auto_quarantine_known" value="1" <?php checked( ! empty( $settings['auto_quarantine_known'] ) ); ?> /> <?php esc_html_e( 'Automatically quarantine only exact known-malicious plugin names after a scheduled scan.', 'aio-malicious-extension-guard' ); ?></label><p class="description"><?php esc_html_e( 'Approval enforcement allows reviewed plugins to be updated, then flags their changed version or checksum for review. It does not replace controlled updates or server-level file restrictions.', 'aio-malicious-extension-guard' ); ?></p></td></tr>
				<tr><th scope="row"><label for="aiomeg-monitor-urls"><?php esc_html_e( 'Public-page monitoring', 'aio-malicious-extension-guard' ); ?></label></th><td><label><input type="checkbox" name="external_monitor" value="1" <?php checked( ! empty( $settings['external_monitor'] ) ); ?> /> <?php esc_html_e( 'Check the public homepage and the URLs below for fake verification patterns during each scan.', 'aio-malicious-extension-guard' ); ?></label><textarea id="aiomeg-monitor-urls" name="monitor_urls" rows="4" class="large-text" placeholder="https://example.com/important-page/"><?php echo esc_textarea( $settings['monitor_urls'] ); ?></textarea><p class="description"><?php esc_html_e( 'Optional public URLs, one per line. The plugin stores only response status and matching indicator words, never the page content.', 'aio-malicious-extension-guard' ); ?></p></td></tr>
				<tr><th scope="row"><label for="aiomeg-approved-admins"><?php esc_html_e( 'Approved administrator accounts', 'aio-malicious-extension-guard' ); ?></label></th><td><textarea id="aiomeg-approved-admins" name="approved_admins" rows="4" class="large-text" placeholder="neil, neil@example.com"><?php echo esc_textarea( $settings['approved_admins'] ); ?></textarea><p class="description"><?php esc_html_e( 'Only listed login names or email addresses are approved for one-click administrator cleanup. Leave this blank to disable user removal.', 'aio-malicious-extension-guard' ); ?></p><label><input type="checkbox" name="cleanup_unapproved_admins" value="1" <?php checked( ! empty( $settings['cleanup_unapproved_admins'] ) ); ?> /> <?php esc_html_e( 'Permit one-click cleanup to remove unapproved administrator accounts, except the current user and all Super Admins.', 'aio-malicious-extension-guard' ); ?></label></td></tr>
				<tr><th scope="row"><?php esc_html_e( 'Data retention', 'aio-malicious-extension-guard' ); ?></th><td><label><input type="checkbox" name="delete_data_on_uninstall" value="1" <?php checked( ! empty( $settings['delete_data_on_uninstall'] ) ); ?> /> <?php esc_html_e( 'Delete AIO Malicious Extension Guard settings, scan records, baseline, approval ledger, health data, and audit log when the plugin is uninstalled.', 'aio-malicious-extension-guard' ); ?></label><p class="description"><?php esc_html_e( 'Off by default. Quarantined files and the standalone MU guard are never removed automatically, so a protective record remains available for review.', 'aio-malicious-extension-guard' ); ?></p></td></tr>
				</tbody></table>
				<?php submit_button( __( 'Save Monitoring Settings', 'aio-malicious-extension-guard' ), 'primary', 'aiomeg_save_settings' ); ?>
			</form>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top: 10px;">
				<input type="hidden" name="action" value="aiomeg_test_email" />
				<?php wp_nonce_field( 'aiomeg_test_email' ); ?>
				<?php submit_button( __( 'Send Branded Test Email', 'aio-malicious-extension-guard' ), 'secondary', 'aiomeg_send_test_email', false ); ?>
				<p class="description"><?php esc_html_e( 'Sends the calm, no-infection email layout to the site administrator and configured security recipients. It does not run a scan or change any settings.', 'aio-malicious-extension-guard' ); ?></p>
			</form>
			<?php if ( $has_initial_scan ) : ?>
				<h2><?php esc_html_e( 'Approved Plugin Inventory', 'aio-malicious-extension-guard' ); ?></h2>
				<p><?php esc_html_e( 'Approve only the plugins you have reviewed. Approval records the version, main-file checksum, and a deterministic fingerprint of every regular file in that plugin directory. It does not approve a publisher or guarantee safety.', 'aio-malicious-extension-guard' ); ?></p>
				<?php $this->render_inventory( $inventory, $settings, $results ); ?>
			<?php endif; ?>
			<h2><?php esc_html_e( 'One-Click Incident Cleanup', 'aio-malicious-extension-guard' ); ?></h2>
			<p><?php esc_html_e( 'Fresh-scans the site, quarantines critical findings from active locations, and optionally removes explicitly unapproved administrator accounts. Quarantined files are preserved for review.', 'aio-malicious-extension-guard' ); ?></p>
			<p class="description"><?php esc_html_e( 'False-positive workflow: export the evidence, review the file and its publisher, and use Restore Without Activating only after a qualified reviewer documents why the finding is safe. Review-level findings are never quarantined automatically.', 'aio-malicious-extension-guard' ); ?></p>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"><input type="hidden" name="action" value="aiomeg_cleanup" /><?php wp_nonce_field( 'aiomeg_cleanup' ); ?><p><label><input type="checkbox" name="aiomeg_acknowledge_cleanup" value="1" required="required" /> <?php esc_html_e( 'I understand this will quarantine critical findings and may remove unapproved administrator accounts only if that optional setting is enabled.', 'aio-malicious-extension-guard' ); ?></label></p><?php submit_button( __( 'Run Incident Cleanup', 'aio-malicious-extension-guard' ), 'delete', 'aiomeg_run_cleanup', false ); ?></form>
			<p><strong><?php esc_html_e( 'Stronger server-level lock:', 'aio-malicious-extension-guard' ); ?></strong> <code>define( 'DISALLOW_FILE_MODS', true );</code> <?php esc_html_e( 'in wp-config.php disables dashboard plugin/theme installation, updates, and edits.', 'aio-malicious-extension-guard' ); ?></p>
			<?php $guard = self::guard_status(); ?>
			<h2><?php esc_html_e( 'Early-Boot MU Guard', 'aio-malicious-extension-guard' ); ?></h2>
			<?php if ( $guard['verified'] ) : ?>
				<p><strong><?php esc_html_e( 'Installed and verified.', 'aio-malicious-extension-guard' ); ?></strong> <?php esc_html_e( 'The guard loads before ordinary plugins and prevents known malicious plugin identifiers from being activated.', 'aio-malicious-extension-guard' ); ?></p>
			<?php else : ?>
				<p><strong><?php esc_html_e( 'Not verified.', 'aio-malicious-extension-guard' ); ?></strong> <?php echo esc_html( isset( $guard['last_attempt']['message'] ) ? $guard['last_attempt']['message'] : __( 'The guard has not yet been installed.', 'aio-malicious-extension-guard' ) ); ?></p>
			<?php endif; ?>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline-block;margin-right:8px"><input type="hidden" name="action" value="aiomeg_install_guard" /><?php wp_nonce_field( 'aiomeg_install_guard' ); ?><?php submit_button( __( 'Install or Repair MU Guard', 'aio-malicious-extension-guard' ), 'secondary', 'aiomeg_install_guard_button', false ); ?></form>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline-block"><input type="hidden" name="action" value="aiomeg_download_guard" /><?php wp_nonce_field( 'aiomeg_download_guard' ); ?><?php submit_button( __( 'Download MU Guard', 'aio-malicious-extension-guard' ), 'secondary', 'aiomeg_download_guard_button', false ); ?></form>
			<p class="description"><?php esc_html_e( 'Expected target:', 'aio-malicious-extension-guard' ); ?> <code><?php echo esc_html( $guard['target'] ); ?></code>. <?php esc_html_e( 'If automated installation is blocked by hosting permissions, upload the downloaded file to that exact location.', 'aio-malicious-extension-guard' ); ?></p>
			<?php $this->render_results( $results ); ?>
			<?php $this->render_quarantine_restore(); ?>
			<h2><?php esc_html_e( 'Security Evidence', 'aio-malicious-extension-guard' ); ?></h2>
			<p><?php esc_html_e( 'Download a JSON evidence report containing scan results, integrity changes, health checks, public-page results, plugin inventory, and cleanup history. Keep it with the incident ticket or client record.', 'aio-malicious-extension-guard' ); ?></p>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"><input type="hidden" name="action" value="aiomeg_export_evidence" /><?php wp_nonce_field( 'aiomeg_export_evidence' ); ?><?php submit_button( __( 'Download Security Evidence', 'aio-malicious-extension-guard' ), 'secondary', 'aiomeg_export_evidence_button', false ); ?></form>
			<?php $this->render_cleanup_log(); ?>
		</div>
		<?php
	}

	private function render_scan_button( $initial = false ) {
		$label = $initial ? __( 'Run Initial Scan', 'aio-malicious-extension-guard' ) : __( 'Run Security Scan', 'aio-malicious-extension-guard' );
		echo '<button type="button" class="button button-primary aiomeg-run-scan">' . esc_html( $label ) . '</button>';
		echo '<div class="aiomeg-scan-progress" hidden="hidden" aria-live="polite"><p>' . esc_html__( 'Scanning plugins, must-use plugins, drop-ins, and executable uploads. This can take a few minutes on larger sites.', 'aio-malicious-extension-guard' ) . '</p><div class="aiomeg-progress-track" role="progressbar" aria-label="' . esc_attr__( 'Security scan in progress', 'aio-malicious-extension-guard' ) . '" aria-valuetext="' . esc_attr__( 'Scan in progress', 'aio-malicious-extension-guard' ) . '"><span></span></div></div>';
		echo '<noscript><form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="aiomeg-scan-fallback"><input type="hidden" name="action" value="aiomeg_scan" />';
		wp_nonce_field( 'aiomeg_scan' );
		submit_button( $label, 'primary', 'aiomeg_run_scan_fallback', false );
		echo '</form></noscript>';
	}

	private function notify_if_actionable( $results, $health = array(), $external = array() ) {
		$critical = array_values( array_filter( $results['findings'], function( $finding ) { return 'critical' === $finding['severity']; } ) );
		$integrity = isset( $results['integrity'] ) ? $results['integrity'] : array();
		$changed = ! empty( $integrity['added'] ) || ! empty( $integrity['modified'] ) || ! empty( $integrity['removed'] );
		$health_issues = isset( $health['issues'] ) ? $health['issues'] : array();
		$suspicious_pages = AIOMEG_Monitor::suspicious_external_checks( $external );
		if ( empty( $critical ) && ! $changed && empty( $health_issues ) && empty( $suspicious_pages ) ) {
			return;
		}
		$fingerprint = hash( 'sha256', wp_json_encode( array( 'critical' => $critical, 'integrity' => $integrity, 'health' => $health_issues, 'external' => $suspicious_pages ) ) );
		if ( hash_equals( (string) get_option( self::OPTION_ALERT, '' ), $fingerprint ) ) {
			return;
		}
		$critical_health = array_values( array_filter( $health_issues, function( $issue ) { return isset( $issue['severity'] ) && 'critical' === $issue['severity']; } ) );
		$details = array();
		foreach ( $critical as $finding ) { $details[] = 'Critical finding: ' . $finding['file']; }
		if ( $changed ) { $details[] = sprintf( 'Recorded code-file changes: %d added, %d modified, %d removed.', count( $integrity['added'] ), count( $integrity['modified'] ), count( $integrity['removed'] ) ); }
		foreach ( $health_issues as $issue ) { $details[] = ucfirst( $issue['severity'] ) . ': ' . $issue['message']; }
		foreach ( $suspicious_pages as $page ) { $details[] = 'Suspected fake verification page: ' . $page['url']; }
		if ( ! empty( $critical ) || ! empty( $critical_health ) || ! empty( $suspicious_pages ) ) {
			$this->send_notification( __( 'Action required: security finding detected', 'aio-malicious-extension-guard' ), $details, 'urgent', $results['scanned_at'] );
		} elseif ( ! empty( $health_issues ) ) {
			$this->send_notification( __( 'Monitoring attention recommended: no infection found', 'aio-malicious-extension-guard' ), $details, 'attention', $results['scanned_at'] );
		} else {
			$this->send_notification( __( 'Security check complete: no infection found', 'aio-malicious-extension-guard' ), $details, 'clear', $results['scanned_at'] );
		}
		update_option( self::OPTION_ALERT, $fingerprint, false );
	}

	private function send_notification( $subject, $lines, $state = 'urgent', $scanned_at = '' ) {
		$recipients = $this->notification_recipients();
		if ( ! empty( $recipients ) ) {
			return wp_mail( $recipients, '[AIO Malicious Extension Guard] ' . $subject, $this->notification_email( $lines, $state, $scanned_at ), array( 'Content-Type: text/html; charset=UTF-8' ) );
		}

		return false;
	}

	private function notification_email( $details, $state, $scanned_at ) {
		$copy = array(
			'urgent' => array(
				'eyebrow' => __( 'Security attention needed', 'aio-malicious-extension-guard' ),
				'headline' => __( 'A security issue needs review', 'aio-malicious-extension-guard' ),
				'intro' => __( 'AIO Malicious Extension Guard identified a critical malware indicator, a fake-verification pattern, or a failed protection layer.', 'aio-malicious-extension-guard' ),
				'action' => __( 'Please have an authorized administrator review AIO Malicious Extension Guard as soon as possible.', 'aio-malicious-extension-guard' ),
				'color' => '#b42318',
				'background' => '#fef3f2',
			),
			'attention' => array(
				'eyebrow' => __( 'Monitoring status update', 'aio-malicious-extension-guard' ),
				'headline' => __( 'No known infection was found', 'aio-malicious-extension-guard' ),
				'intro' => __( 'The scan did not find a known x-dav or fake-verification infection. A monitoring condition should be reviewed by the site administrator or AIO technical team.', 'aio-malicious-extension-guard' ),
				'action' => __( 'No emergency response is indicated, but please review the monitoring note below.', 'aio-malicious-extension-guard' ),
				'color' => '#9a6700',
				'background' => '#fffaeb',
			),
			'clear' => array(
				'eyebrow' => __( 'Security monitoring update', 'aio-malicious-extension-guard' ),
				'headline' => __( 'No infection or reinfection found', 'aio-malicious-extension-guard' ),
				'intro' => __( 'AIO Malicious Extension Guard did not identify a known x-dav, fake-verification, or other critical malware indicator during this scan.', 'aio-malicious-extension-guard' ),
				'action' => __( 'No immediate action is required from you. A recorded file change is included below for AIO technical records and does not mean an infection was found.', 'aio-malicious-extension-guard' ),
				'color' => '#067647',
				'background' => '#ecfdf3',
			),
		);
		$copy = isset( $copy[ $state ] ) ? $copy[ $state ] : $copy['urgent'];
		$items = '';
		foreach ( $details as $detail ) {
			$items .= '<li style="margin:0 0 8px;line-height:1.5;color:#344054">' . esc_html( $detail ) . '</li>';
		}
		if ( '' === $items ) {
			$items = '<li style="margin:0;line-height:1.5;color:#344054">' . esc_html__( 'No additional scan details were recorded.', 'aio-malicious-extension-guard' ) . '</li>';
		}
		$tools_url = admin_url( 'tools.php?page=aio-malicious-extension-guard' );
		/* translators: %s: scan completion time in UTC. */
		$completed_at = sprintf( __( 'Scan completed: %s UTC.', 'aio-malicious-extension-guard' ), $scanned_at );
		return '<!doctype html><html><body style="margin:0;padding:0;background:#f2f4f7;font-family:Arial,sans-serif;color:#101828"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f2f4f7;padding:28px 12px"><tr><td align="center"><table role="presentation" width="600" cellspacing="0" cellpadding="0" style="max-width:600px;width:100%;background:#ffffff;border-radius:8px;overflow:hidden"><tr><td align="center" style="padding:30px 24px 18px"><img src="' . esc_url( AIOMEG_URL . 'assets/aio-logo.png' ) . '" width="150" alt="AIO Web Designs" style="display:block;border:0;max-width:150px;height:auto" /></td></tr><tr><td style="padding:0 32px 30px"><p style="margin:0 0 8px;color:#1ca4df;font-size:13px;font-weight:bold;letter-spacing:.8px;text-transform:uppercase">' . esc_html( $copy['eyebrow'] ) . '</p><h1 style="margin:0 0 14px;font-size:26px;line-height:1.25;color:#101828">' . esc_html( $copy['headline'] ) . '</h1><p style="margin:0 0 18px;font-size:16px;line-height:1.55;color:#344054">' . esc_html( $copy['intro'] ) . '</p><div style="margin:0 0 22px;padding:14px 16px;background:' . esc_attr( $copy['background'] ) . ';border-left:4px solid ' . esc_attr( $copy['color'] ) . ';color:#101828;font-size:15px;line-height:1.5"><strong>' . esc_html( $copy['action'] ) . '</strong></div><h2 style="margin:0 0 10px;font-size:16px;color:#101828">' . esc_html__( 'Scan details', 'aio-malicious-extension-guard' ) . '</h2><ul style="margin:0 0 20px;padding-left:20px">' . $items . '</ul><p style="margin:0;font-size:13px;line-height:1.5;color:#667085">' . esc_html( $completed_at ) . ' <a href="' . esc_url( $tools_url ) . '" style="color:#087db8;text-decoration:underline">' . esc_html__( 'Open AIO Malicious Extension Guard', 'aio-malicious-extension-guard' ) . '</a></p></td></tr><tr><td align="center" style="padding:18px 24px;background:#f9fafb;border-top:1px solid #eaecf0;font-size:12px;line-height:1.5;color:#667085">AIO Malicious Extension Guard by <a href="https://aiowebdesigns.com/" style="color:#087db8;text-decoration:underline">AIO Web Designs</a></td></tr></table></td></tr></table></body></html>';
	}

	private function notification_recipients() {
		$emails = array_filter( array_map( 'sanitize_email', preg_split( '/[\s,;]+/', $this->settings()['notification_recipients'] ) ) );
		$emails[] = sanitize_email( get_option( 'admin_email' ) );
		return array_values( array_unique( array_filter( $emails, 'is_email' ) ) );
	}

	private function remove_unapproved_administrators() {
		$settings = $this->settings();
		$approved = preg_split( '/[\s,;]+/', strtolower( $settings['approved_admins'] ) );
		$approved = array_filter( array_map( 'trim', $approved ) );
		if ( empty( $settings['cleanup_unapproved_admins'] ) || empty( $approved ) ) {
			return array();
		}
		require_once ABSPATH . 'wp-admin/includes/user.php';
		$removed = array();
		$current_user = get_current_user_id();
		foreach ( get_users( array( 'role' => 'administrator', 'fields' => array( 'ID', 'user_login', 'user_email' ) ) ) as $user ) {
			if ( (int) $user->ID === (int) $current_user || ( is_multisite() && is_super_admin( $user->ID ) ) || in_array( strtolower( $user->user_login ), $approved, true ) || in_array( strtolower( $user->user_email ), $approved, true ) ) {
				continue;
			}
			if ( wp_delete_user( $user->ID, $current_user ) ) {
				$removed[] = $user->user_login;
			}
		}
		return $removed;
	}

	private function write_cleanup_log( $cleanup, $removed_users ) {
		$entries = get_option( self::OPTION_CLEANUP_LOG, array() );
		array_unshift( $entries, array( 'time' => current_time( 'mysql', true ), 'files' => $cleanup['actions'], 'errors' => $cleanup['errors'], 'users' => $removed_users ) );
		update_option( self::OPTION_CLEANUP_LOG, array_slice( $entries, 0, 20 ), false );
	}

	private function render_notices() {
		// These query values only render a post-redirect notice; they do not perform an action.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Display-only data created by a nonce-protected action.
		$notice = isset( $_GET['aiomeg_notice'] ) ? sanitize_key( wp_unslash( $_GET['aiomeg_notice'] ) ) : '';
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Display-only data created by a nonce-protected action.
		$error = isset( $_GET['aiomeg_error'] ) ? sanitize_text_field( wp_unslash( $_GET['aiomeg_error'] ) ) : '';
		if ( $notice ) {
			$messages = array( 'scanned' => __( 'Security scan completed.', 'aio-malicious-extension-guard' ), 'baseline' => __( 'Clean baseline saved.', 'aio-malicious-extension-guard' ), 'settings' => __( 'Monitoring settings saved.', 'aio-malicious-extension-guard' ), 'test_email_sent' => __( 'Branded test email sent to the site administrator and configured security recipients.', 'aio-malicious-extension-guard' ), 'cleaned' => __( 'Incident cleanup completed.', 'aio-malicious-extension-guard' ), 'nothing_to_clean' => __( 'No critical finding or unapproved approved-list administrator required cleanup.', 'aio-malicious-extension-guard' ), 'inventory_approved' => __( 'Selected plugin approvals were recorded.', 'aio-malicious-extension-guard' ), 'inventory_revoked' => __( 'Selected plugin approvals were revoked. The plugins themselves were not changed.', 'aio-malicious-extension-guard' ), 'restored' => __( 'The quarantined item was restored but was not activated.', 'aio-malicious-extension-guard' ) );
			$notice_class = 'notice-success';
			if ( 'cleaned' === $notice ) {
				$feedback = get_transient( 'aiomeg_cleanup_feedback_' . get_current_user_id() );
				delete_transient( 'aiomeg_cleanup_feedback_' . get_current_user_id() );
				$action_count = is_array( $feedback ) && isset( $feedback['actions'] ) ? count( $feedback['actions'] ) : 0;
				$error_count = is_array( $feedback ) && isset( $feedback['errors'] ) ? count( $feedback['errors'] ) : 0;
				if ( $action_count ) {
					$messages['cleaned'] = sprintf( _n( 'Incident cleanup completed. %d critical item was moved to protected quarantine; it was not permanently deleted.', 'Incident cleanup completed. %d critical items were moved to protected quarantine; they were not permanently deleted.', $action_count, 'aio-malicious-extension-guard' ), $action_count );
				}
				if ( $error_count ) {
					$notice_class = 'notice-error';
					$messages['cleaned'] .= ' ' . __( 'One or more items could not be quarantined and need further investigation.', 'aio-malicious-extension-guard' );
				}
			}
			echo '<div class="notice ' . esc_attr( $notice_class ) . ' aiomeg-outcome-notice" data-aiomeg-toast="' . esc_attr( 'notice-error' === $notice_class ? 'error' : 'success' ) . '"><p>' . esc_html( isset( $messages[ $notice ] ) ? $messages[ $notice ] : __( 'Action completed.', 'aio-malicious-extension-guard' ) ) . '</p></div>';
		}
		if ( $error ) { echo '<div class="notice notice-error"><p>' . esc_html( rawurldecode( $error ) ) . '</p></div>'; }
		if ( $blocked = get_transient( 'aiomeg_activation_blocked' ) ) { echo '<div class="notice notice-error"><p>' . esc_html__( 'Blocked plugin activation: ', 'aio-malicious-extension-guard' ) . esc_html( $blocked ) . '</p></div>'; }
	}

	private function render_health( $health, $external ) {
		echo '<h2>' . esc_html__( 'Protection Health', 'aio-malicious-extension-guard' ) . '</h2>';
		$issues = isset( $health['issues'] ) ? $health['issues'] : array();
		if ( empty( $issues ) ) {
			echo '<p><strong>' . esc_html__( 'Guard, scan schedule, and scan freshness checks are healthy.', 'aio-malicious-extension-guard' ) . '</strong></p>';
		} else {
			echo '<ul>';
			foreach ( $issues as $issue ) {
				echo '<li><strong>' . esc_html( ucfirst( $issue['severity'] ) ) . '</strong>: ' . esc_html( $issue['message'] ) . '</li>';
			}
			echo '</ul>';
		}
		if ( ! empty( $health['next_scan'] ) ) {
			/* translators: %s: next scheduled scan time in UTC. */
			echo '<p>' . sprintf( esc_html__( 'Next scheduled scan (UTC): %s.', 'aio-malicious-extension-guard' ), esc_html( $health['next_scan'] ) ) . '</p>';
		}
		if ( empty( $external['enabled'] ) ) {
			echo '<p class="description">' . esc_html__( 'Public-page monitoring is currently off.', 'aio-malicious-extension-guard' ) . '</p>';
		} elseif ( empty( $external['checks'] ) ) {
			echo '<p class="description">' . esc_html__( 'Public-page monitoring is enabled and will run with the next scan.', 'aio-malicious-extension-guard' ) . '</p>';
		} else {
			$suspicious = AIOMEG_Monitor::suspicious_external_checks( $external );
			echo '<p><strong>' . ( empty( $suspicious ) ? esc_html__( 'Public-page check: no fake-verification pattern detected.', 'aio-malicious-extension-guard' ) : esc_html__( 'Public-page check: suspected fake-verification pattern detected.', 'aio-malicious-extension-guard' ) ) . '</strong></p>';
			if ( ! empty( $suspicious ) ) {
				echo '<ul>';
				foreach ( $suspicious as $check ) { echo '<li><code>' . esc_html( $check['url'] ) . '</code> (' . esc_html( implode( ', ', $check['markers'] ) ) . ')</li>'; }
				echo '</ul>';
			}
		}
	}

	private function render_inventory( $inventory, $settings, $results = array() ) {
		if ( empty( $inventory ) ) {
			echo '<p>' . esc_html__( 'No standard plugins were found.', 'aio-malicious-extension-guard' ) . '</p>';
			return;
		}
		$review = array_filter( $inventory, function( $plugin ) { return empty( $plugin['approved'] ); } );
		$approved = array_filter( $inventory, function( $plugin ) { return ! empty( $plugin['approved'] ); } );
		$critical = array_values( array_filter( isset( $results['findings'] ) ? $results['findings'] : array(), function( $finding ) {
			return isset( $finding['severity'] ) && 'critical' === $finding['severity'];
		} ) );
		if ( ! empty( $review ) ) {
			echo '<h3>' . esc_html__( 'Plugins Requiring Review', 'aio-malicious-extension-guard' ) . '</h3>';
			if ( ! empty( $critical ) ) {
				echo '<div class="aiomeg-inventory-blocked"><strong>' . esc_html__( 'Plugin approvals are temporarily locked.', 'aio-malicious-extension-guard' ) . '</strong> ' . esc_html( sprintf( _n( 'The latest scan has %d critical finding that must be resolved or quarantined before any plugins can be approved.', 'The latest scan has %d critical findings that must be resolved or quarantined before any plugins can be approved.', count( $critical ), 'aio-malicious-extension-guard' ), count( $critical ) ) ) . '<ul>';
				foreach ( $critical as $finding ) {
					echo '<li><code>' . esc_html( isset( $finding['file'] ) ? $finding['file'] : '' ) . '</code></li>';
				}
				echo '</ul><p>' . esc_html__( 'Use One-Click Incident Cleanup below to move only these critical items to quarantine. It does not permanently delete them.', 'aio-malicious-extension-guard' ) . '</p></div>';
				echo '<p class="description">' . esc_html__( 'The plugin selection list is intentionally hidden until critical findings are handled. This prevents an administrator from accidentally approving a suspicious plugin.', 'aio-malicious-extension-guard' ) . '</p>';
				return;
			}
			echo '<p class="description"><strong>' . esc_html__( 'A security scan alone does not approve plugins.', 'aio-malicious-extension-guard' ) . '</strong> ' . esc_html__( 'Select the reviewed plugins below, confirm the acknowledgment, then use Save Selected Plugin Approvals. AIO Malicious Extension Guard runs a fresh scan as part of that save.', 'aio-malicious-extension-guard' ) . '</p>';
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="aiomeg-inventory-form"><input type="hidden" name="action" value="aiomeg_approve_inventory" />';
			wp_nonce_field( 'aiomeg_approve_inventory' );
			echo '<table class="widefat striped aiomeg-inventory"><thead><tr><th class="check-column"><span class="screen-reader-text">' . esc_html__( 'Select', 'aio-malicious-extension-guard' ) . '</span></th><th>' . esc_html__( 'Plugin', 'aio-malicious-extension-guard' ) . '</th><th>' . esc_html__( 'Version', 'aio-malicious-extension-guard' ) . '</th><th>' . esc_html__( 'State', 'aio-malicious-extension-guard' ) . '</th><th>' . esc_html__( 'Directory Integrity', 'aio-malicious-extension-guard' ) . '</th></tr></thead><tbody>';
			foreach ( $review as $plugin ) {
				$this->render_inventory_row( $plugin, true );
			}
			echo '</tbody></table>';
			echo '<p><label><input type="checkbox" name="aiomeg_acknowledge_inventory" value="1" required="required" /> ' . esc_html__( 'I reviewed the selected plugin directories and understand approval records their current state for this website.', 'aio-malicious-extension-guard' ) . '</label></p>';
			submit_button( __( 'Save Selected Plugin Approvals', 'aio-malicious-extension-guard' ), 'primary', 'aiomeg_approve_inventory_button', false, ! empty( $critical ) ? array( 'disabled' => 'disabled', 'title' => __( 'Resolve the critical findings shown above before saving approvals.', 'aio-malicious-extension-guard' ) ) : array() );
			echo '</form>';
		} else {
			echo '<p class="aiomeg-inventory-clear"><strong>' . esc_html__( 'All installed plugins are currently approved and unchanged.', 'aio-malicious-extension-guard' ) . '</strong> ' . esc_html__( 'Expand the section below to review or revoke an approval.', 'aio-malicious-extension-guard' ) . '</p>';
		}

		if ( ! empty( $approved ) ) {
			echo '<details class="aiomeg-approved-inventory"><summary>' . esc_html( sprintf( _n( '%d Previously Approved Plugin', '%d Previously Approved Plugins', count( $approved ), 'aio-malicious-extension-guard' ), count( $approved ) ) ) . '</summary>';
			echo '<p class="description">' . esc_html__( 'These entries are hidden from the main review list because their approved version and full-directory fingerprint still match. Revoking an approval does not disable, update, or remove the plugin.', 'aio-malicious-extension-guard' ) . '</p>';
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="aiomeg-inventory-form"><input type="hidden" name="action" value="aiomeg_revoke_inventory" />';
			wp_nonce_field( 'aiomeg_revoke_inventory' );
			echo '<table class="widefat striped aiomeg-inventory"><thead><tr><th class="check-column"><span class="screen-reader-text">' . esc_html__( 'Select', 'aio-malicious-extension-guard' ) . '</span></th><th>' . esc_html__( 'Plugin', 'aio-malicious-extension-guard' ) . '</th><th>' . esc_html__( 'Version', 'aio-malicious-extension-guard' ) . '</th><th>' . esc_html__( 'State', 'aio-malicious-extension-guard' ) . '</th><th>' . esc_html__( 'Approved', 'aio-malicious-extension-guard' ) . '</th></tr></thead><tbody>';
			foreach ( $approved as $plugin ) {
				$this->render_inventory_row( $plugin, true, true );
			}
			echo '</tbody></table>';
			submit_button( __( 'Revoke Selected Approvals', 'aio-malicious-extension-guard' ), 'secondary', 'aiomeg_revoke_inventory_button', false, array( 'onclick' => "return confirm('This removes only the selected approval records. The plugins will remain installed and unchanged. Continue?');" ) );
			echo '</form></details>';
		}
		if ( ! empty( $settings['enforce_plugin_approval'] ) ) {
			echo '<p class="description">' . esc_html__( 'Approval enforcement is enabled. New or changed plugin files move back into the review list.', 'aio-malicious-extension-guard' ) . '</p>';
		}
	}

	private function render_inventory_row( $plugin, $selectable = false, $show_approved_meta = false ) {
			$state = $plugin['active'] ? __( 'Active', 'aio-malicious-extension-guard' ) : __( 'Inactive', 'aio-malicious-extension-guard' );
			/* translators: %d: number of plugin files included in the directory fingerprint. */
			$integrity = $plugin['directory_complete'] ? sprintf( _n( '%d file fingerprinted', '%d files fingerprinted', $plugin['directory_file_count'], 'aio-malicious-extension-guard' ), $plugin['directory_file_count'] ) : __( 'Incomplete fingerprint - review required', 'aio-malicious-extension-guard' );
			/* translators: 1: inventory approval time in UTC, 2: administrator who approved it. */
			$approved_meta = $plugin['approved'] && $plugin['approved_at'] ? sprintf( __( '%1$s by %2$s', 'aio-malicious-extension-guard' ), $plugin['approved_at'], $plugin['approved_by'] ? $plugin['approved_by'] : __( 'an administrator', 'aio-malicious-extension-guard' ) ) : '';
			echo '<tr>';
		if ( $selectable ) {
			echo '<th scope="row" class="check-column"><input type="checkbox" name="aiomeg_plugins[]" value="' . esc_attr( $plugin['file'] ) . '" /></th>';
		}
			echo '<td><code>' . esc_html( $plugin['file'] ) . '</code><br />' . esc_html( $plugin['name'] ) . '</td><td>' . esc_html( $plugin['version'] ) . '</td><td>' . esc_html( $state ) . '</td>';
			echo '<td>' . esc_html( $show_approved_meta ? ( $approved_meta ? $approved_meta : __( 'Approved', 'aio-malicious-extension-guard' ) ) : $integrity ) . '</td></tr>';
	}

	private function render_update_exposure( $exposure ) {
		$plugin_count = count( isset( $exposure['plugin_updates'] ) ? $exposure['plugin_updates'] : array() );
		echo '<h2>' . esc_html__( 'Update Exposure', 'aio-malicious-extension-guard' ) . '</h2>';
		if ( empty( $exposure['core_update_available'] ) && ! $plugin_count ) {
			echo '<p><strong>' . esc_html__( 'WordPress currently reports no core or plugin updates.', 'aio-malicious-extension-guard' ) . '</strong></p>';
		} else {
			/* translators: 1: number of available WordPress core updates, 2: number of available plugin updates. */
			echo '<p>' . sprintf( esc_html__( 'WordPress reports %1$d core update(s) and %2$d plugin update(s). Review releases before approving and installing them.', 'aio-malicious-extension-guard' ), ! empty( $exposure['core_update_available'] ) ? 1 : 0, absint( $plugin_count ) ) . '</p>';
			if ( $plugin_count ) {
				echo '<ul>';
				foreach ( $exposure['plugin_updates'] as $plugin_file ) { echo '<li><code>' . esc_html( $plugin_file ) . '</code></li>'; }
				echo '</ul>';
			}
		}
		echo '<p class="description">' . esc_html__( 'Update availability is not a vulnerability verdict. AIO Malicious Extension Guard does not claim to provide a live vulnerability intelligence feed.', 'aio-malicious-extension-guard' ) . '</p>';
	}

	private function render_quarantine_restore() {
		$entries = $this->scanner->quarantine_entries();
		if ( empty( $entries ) ) {
			return;
		}
		echo '<h2>' . esc_html__( 'Quarantine Recovery', 'aio-malicious-extension-guard' ) . '</h2><p>' . esc_html__( 'A restore only moves the selected item back to its original location. It does not activate a restored plugin. Restore only after a qualified review confirms the finding was a false positive.', 'aio-malicious-extension-guard' ) . '</p>';
		echo '<table class="widefat striped"><thead><tr><th>' . esc_html__( 'Quarantined (UTC)', 'aio-malicious-extension-guard' ) . '</th><th>' . esc_html__( 'Original location', 'aio-malicious-extension-guard' ) . '</th><th>' . esc_html__( 'Action', 'aio-malicious-extension-guard' ) . '</th></tr></thead><tbody>';
		foreach ( $entries as $entry ) {
			echo '<tr><td>' . esc_html( $entry['time'] ) . '</td><td><code>' . esc_html( $entry['source_path'] ) . '</code></td><td><form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="aiomeg_restore_quarantine" /><input type="hidden" name="aiomeg_quarantine_token" value="' . esc_attr( $entry['token'] ) . '" />';
			wp_nonce_field( 'aiomeg_restore_quarantine' );
			echo '<input type="submit" class="button" value="' . esc_attr__( 'Restore Without Activating', 'aio-malicious-extension-guard' ) . '" onclick="return confirm(\'This will return the quarantined code to its original location without activating it. Continue only if the finding has been reviewed as a false positive.\');" /></form></td></tr>';
		}
		echo '</tbody></table>';
	}

	private function render_results( $results ) {
		echo '<h2>' . esc_html__( 'Latest Scan', 'aio-malicious-extension-guard' ) . '</h2>';
		if ( empty( $results['scanned_at'] ) ) { echo '<p>' . esc_html__( 'No scan has run yet.', 'aio-malicious-extension-guard' ) . '</p>'; return; }
		/* translators: 1: scan completion time in UTC, 2: number of files reviewed. */
		echo '<p>' . sprintf( esc_html__( 'Last scan (UTC): %1$s. Files reviewed: %2$d.', 'aio-malicious-extension-guard' ), esc_html( $results['scanned_at'] ), (int) $results['file_count'] ) . '</p>';
		if ( empty( $results['findings'] ) ) { echo '<p><strong>' . esc_html__( 'No known x-dav indicators or high-risk code combinations were found.', 'aio-malicious-extension-guard' ) . '</strong></p>'; }
		else { echo '<ul>'; foreach ( $results['findings'] as $finding ) { echo '<li><strong>' . esc_html( ucfirst( $finding['severity'] ) ) . '</strong>: <code>' . esc_html( $finding['file'] ) . '</code> (' . esc_html( implode( ', ', $finding['markers'] ) ?: __( 'known malicious directory name', 'aio-malicious-extension-guard' ) ) . ')</li>'; } echo '</ul>'; }
		$integrity = isset( $results['integrity'] ) ? $results['integrity'] : array();
		if ( ! empty( $integrity['available'] ) ) { /* translators: 1: added files, 2: modified files, 3: removed files. */ echo '<p>' . sprintf( esc_html__( 'Baseline changes: %1$d added, %2$d modified, %3$d removed.', 'aio-malicious-extension-guard' ), count( $integrity['added'] ), count( $integrity['modified'] ), count( $integrity['removed'] ) ) . '</p>'; }
		else { echo '<p>' . esc_html__( 'No integrity baseline exists yet.', 'aio-malicious-extension-guard' ) . '</p>'; }
	}

	private function render_cleanup_log() {
		$entries = get_option( self::OPTION_CLEANUP_LOG, array() );
		if ( empty( $entries ) ) { return; }
		echo '<h2>' . esc_html__( 'Cleanup Audit Log', 'aio-malicious-extension-guard' ) . '</h2><table class="widefat striped"><thead><tr><th>' . esc_html__( 'Time (UTC)', 'aio-malicious-extension-guard' ) . '</th><th>' . esc_html__( 'Quarantined', 'aio-malicious-extension-guard' ) . '</th><th>' . esc_html__( 'Removed admins', 'aio-malicious-extension-guard' ) . '</th><th>' . esc_html__( 'Errors', 'aio-malicious-extension-guard' ) . '</th></tr></thead><tbody>';
		foreach ( $entries as $entry ) { echo '<tr><td>' . esc_html( $entry['time'] ) . '</td><td>' . esc_html( implode( ', ', $entry['files'] ) ) . '</td><td>' . esc_html( implode( ', ', $entry['users'] ) ) . '</td><td>' . esc_html( implode( '; ', $entry['errors'] ) ) . '</td></tr>'; }
		echo '</tbody></table>';
	}

	private function settings() { return wp_parse_args( get_option( self::OPTION_SETTINGS, array() ), self::default_settings() ); }

	private function sanitize_recipients( $raw ) {
		$emails = array_filter( array_map( 'sanitize_email', preg_split( '/[\s,;]+/', $raw ) ), 'is_email' );
		return implode( "\n", array_unique( $emails ) );
	}

	private function sanitize_approved_admins( $raw ) {
		$items = preg_split( '/[\s,;]+/', strtolower( sanitize_textarea_field( $raw ) ) );
		return implode( "\n", array_unique( array_filter( array_map( 'sanitize_text_field', $items ) ) ) );
	}

	private function redirect( $args ) { wp_safe_redirect( add_query_arg( $args, admin_url( 'tools.php?page=aio-malicious-extension-guard' ) ) ); exit; }

	private function require_admin_nonce( $action ) {
		if ( ! current_user_can( 'activate_plugins' ) ) { wp_die( esc_html__( 'You are not allowed to manage plugins.', 'aio-malicious-extension-guard' ) ); }
		check_admin_referer( $action );
	}
}
