<?php

defined( 'ABSPATH' ) || exit;

class AIO_PS_Plugin {

	const CRON_HOOK = 'aio_ps_scheduled_scan';
	const OPTION_SETTINGS = 'aio_ps_settings';
	const OPTION_ALERT = 'aio_ps_last_alert_fingerprint';
	const OPTION_CLEANUP_LOG = 'aio_ps_cleanup_log';
	const OPTION_GUARD_STATUS = 'aio_ps_mu_guard_status';
	const GUARD_FILENAME = 'aio-plugin-sentinel-guard.php';
	private static $instance;
	private $scanner;

	public static function instance() {
		if ( ! self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	public static function activate() {
		// Updates and reactivations add new defaults without overwriting site choices.
		self::migrate_settings();
		self::install_mu_guard();
		self::reschedule_scans();
	}

	public static function deactivate() {
		wp_clear_scheduled_hook( self::CRON_HOOK );
	}

	private function __construct() {
		$this->scanner = new AIO_PS_Scanner();
		add_filter( 'cron_schedules', array( $this, 'add_cron_schedules' ) );
		add_action( 'admin_menu', array( $this, 'register_menu' ) );
		add_action( 'admin_post_aio_ps_scan', array( $this, 'handle_scan' ) );
		add_action( 'admin_post_aio_ps_baseline', array( $this, 'handle_baseline' ) );
		add_action( 'admin_post_aio_ps_cleanup', array( $this, 'handle_cleanup' ) );
		add_action( 'admin_post_aio_ps_settings', array( $this, 'handle_settings' ) );
		add_action( 'admin_post_aio_ps_test_email', array( $this, 'handle_test_email' ) );
		add_action( 'admin_post_aio_ps_install_guard', array( $this, 'handle_install_guard' ) );
		add_action( 'admin_post_aio_ps_download_guard', array( $this, 'handle_download_guard' ) );
		add_action( 'admin_post_aio_ps_approve_inventory', array( $this, 'handle_approve_inventory' ) );
		add_action( 'admin_post_aio_ps_export_evidence', array( $this, 'handle_export_evidence' ) );
		add_action( 'admin_post_aio_ps_restore_quarantine', array( $this, 'handle_restore_quarantine' ) );
		add_action( self::CRON_HOOK, array( $this, 'run_scheduled_scan' ) );
		add_action( 'plugins_loaded', array( __CLASS__, 'maybe_install_mu_guard' ), 20 );
		add_action( 'init', array( $this, 'load_textdomain' ) );
		add_action( 'admin_init', array( $this, 'record_health' ) );
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

	public function enqueue_admin_assets( $hook_suffix ) {
		if ( 'tools_page_aio-plugin-sentinel' !== $hook_suffix ) {
			return;
		}
		wp_enqueue_style( 'aio-plugin-sentinel-admin', AIO_PS_URL . 'assets/admin.css', array(), AIO_PS_VERSION );
	}

	/**
	 * Allow WordPress.org language packs to translate the administrative interface.
	 */
	public function load_textdomain() {
		load_plugin_textdomain( 'aio-plugin-sentinel', false, dirname( plugin_basename( AIO_PS_FILE ) ) . '/languages' );
	}

	public function add_cron_schedules( $schedules ) {
		$schedules['aio_ps_15_minutes'] = array( 'interval' => 15 * MINUTE_IN_SECONDS, 'display' => __( 'Every 15 Minutes (AIO Plugin Sentinel)', 'aio-plugin-sentinel' ) );
		return $schedules;
	}

	public static function reschedule_scans() {
		wp_clear_scheduled_hook( self::CRON_HOOK );
		$settings = wp_parse_args( get_option( self::OPTION_SETTINGS, array() ), self::default_settings() );
		$schedules = array( 'aio_ps_15_minutes', 'hourly', 'twicedaily', 'daily' );
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
	 * Keep the standalone guard in sync after a Plugin Sentinel update without
	 * touching an unrelated file that happens to share its filename.
	 */
	public static function maybe_install_mu_guard() {
		$status = self::guard_status();
		if ( ! $status['verified'] && $status['source_available'] ) {
			self::install_mu_guard();
		}
	}

	public static function install_mu_guard() {
		$source = self::guard_source_path();
		if ( ! is_readable( $source ) ) {
			return self::save_guard_status( array( 'state' => 'source_unavailable', 'message' => __( 'The bundled MU guard file is unavailable.', 'aio-plugin-sentinel' ) ) );
		}

		$directory = self::guard_directory();
		if ( ! is_dir( $directory ) && ! wp_mkdir_p( $directory ) ) {
			return self::save_guard_status( array( 'state' => 'directory_unavailable', 'message' => __( 'WordPress could not create wp-content/mu-plugins.', 'aio-plugin-sentinel' ) ) );
		}
		if ( ! is_writable( $directory ) ) {
			return self::save_guard_status( array( 'state' => 'directory_not_writable', 'message' => __( 'wp-content/mu-plugins is not writable by WordPress. Download the guard and upload it through the host file manager.', 'aio-plugin-sentinel' ) ) );
		}

		$target = trailingslashit( $directory ) . self::GUARD_FILENAME;
		$source_hash = hash_file( 'sha256', $source );
		$target_hash = is_file( $target ) ? hash_file( 'sha256', $target ) : false;
		if ( $target_hash && hash_equals( $source_hash, $target_hash ) ) {
			return self::save_guard_status( array( 'state' => 'verified', 'message' => __( 'The early-boot MU guard is installed and verified.', 'aio-plugin-sentinel' ), 'hash' => $source_hash ) );
		}

		if ( is_file( $target ) && ! self::backup_existing_guard( $target ) ) {
			return self::save_guard_status( array( 'state' => 'backup_failed', 'message' => __( 'The existing MU guard could not be backed up, so it was not replaced.', 'aio-plugin-sentinel' ) ) );
		}
		if ( ! @copy( $source, $target ) || ! is_file( $target ) || ! hash_equals( $source_hash, (string) hash_file( 'sha256', $target ) ) ) {
			return self::save_guard_status( array( 'state' => 'copy_failed', 'message' => __( 'WordPress could not install and verify the MU guard. Check hosting file permissions.', 'aio-plugin-sentinel' ) ) );
		}

		return self::save_guard_status( array( 'state' => 'verified', 'message' => __( 'The early-boot MU guard is installed and verified.', 'aio-plugin-sentinel' ), 'hash' => $source_hash ) );
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
		return AIO_PS_DIR . 'mu-plugin/' . self::GUARD_FILENAME;
	}

	private static function guard_directory() {
		return defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';
	}

	private static function backup_existing_guard( $target ) {
		$directory = WP_CONTENT_DIR . '/aio-plugin-sentinel-quarantine/mu-guard-backups';
		if ( ! wp_mkdir_p( $directory ) || ! self::protect_guard_backups( $directory ) ) {
			return false;
		}
		// A .txt extension ensures a backup cannot be executed if server rules are bypassed.
		$backup = trailingslashit( $directory ) . gmdate( 'Ymd-His' ) . '-' . self::GUARD_FILENAME . '.txt';
		return @copy( $target, $backup );
	}

	private static function protect_guard_backups( $directory ) {
		$files = array(
			'index.php' => "<?php // Silence is golden.\n",
			'.htaccess' => "Require all denied\nDeny from all\n",
			'web.config' => '<?xml version="1.0"?><configuration><system.webServer><authorization><deny users="*" /></authorization></system.webServer></configuration>',
		);
		foreach ( $files as $name => $contents ) {
			$file = trailingslashit( $directory ) . $name;
			if ( ! is_file( $file ) && false === @file_put_contents( $file, $contents, LOCK_EX ) ) {
				return false;
			}
		}
		return true;
	}

	private static function save_guard_status( $status ) {
		$status['checked_at'] = current_time( 'mysql', true );
		update_option( self::OPTION_GUARD_STATUS, $status, false );
		return $status;
	}

	public function register_menu() {
		add_management_page( __( 'AIO Plugin Sentinel', 'aio-plugin-sentinel' ), __( 'Plugin Sentinel', 'aio-plugin-sentinel' ), 'activate_plugins', 'aio-plugin-sentinel', array( $this, 'render_page' ) );
	}

	/**
	 * Offer administrators accurate, ready-to-use disclosure text for the site's
	 * WordPress privacy-policy guide. The plugin has no telemetry by default.
	 */
	public function add_privacy_policy_content() {
		if ( ! function_exists( 'wp_add_privacy_policy_content' ) ) {
			return;
		}

		$content = '<p>' . esc_html__( 'AIO Plugin Sentinel stores security-monitoring data locally in this WordPress installation. It does not send scan results, website files, WordPress user data, or credentials to AIO Web Designs or another third party.', 'aio-plugin-sentinel' ) . '</p>';
		$content .= '<h2>' . esc_html__( 'Data collected and stored locally', 'aio-plugin-sentinel' ) . '</h2>';
		$content .= '<p>' . esc_html__( 'The plugin records scan timestamps, findings, executable-file hashes, integrity baselines, approved-plugin fingerprints, configured notification-recipient email addresses, scan-health information, and cleanup audit records. These records are used only to operate the security monitoring and incident-response features on this site.', 'aio-plugin-sentinel' ) . '</p>';
		$content .= '<h2>' . esc_html__( 'Network requests and email', 'aio-plugin-sentinel' ) . '</h2>';
		$content .= '<p>' . esc_html__( 'Public-page monitoring is off by default. If an administrator enables it, the plugin requests only this site\'s homepage and administrator-supplied URLs on the same host to check for fake-verification patterns. It stores only the response status and matching indicator words, not the response body. Security notifications are sent through this site\'s configured WordPress mail system only to the site administrator and recipients an administrator enters.', 'aio-plugin-sentinel' ) . '</p>';
		$content .= '<h2>' . esc_html__( 'Retention and deletion', 'aio-plugin-sentinel' ) . '</h2>';
		$content .= '<p>' . esc_html__( 'Security records are retained when the plugin is uninstalled by default so incident evidence is not lost. An administrator can opt in to delete Plugin Sentinel settings, scan records, baselines, approvals, health data, and audit logs during uninstall. Quarantined files and the early-boot MU guard are never removed automatically and require deliberate host-level review.', 'aio-plugin-sentinel' ) . '</p>';

		wp_add_privacy_policy_content( __( 'AIO Plugin Sentinel', 'aio-plugin-sentinel' ), wp_kses_post( $content ) );
	}

	public function handle_scan() {
		$this->require_admin_nonce( 'aio_ps_scan' );
		$this->run_monitoring_cycle();
		$this->redirect( array( 'aio_ps_notice' => 'scanned' ) );
	}

	public function handle_baseline() {
		$this->require_admin_nonce( 'aio_ps_baseline' );
		$result = $this->scanner->create_baseline();
		$this->redirect( is_wp_error( $result ) ? array( 'aio_ps_error' => rawurlencode( $result->get_error_message() ) ) : array( 'aio_ps_notice' => 'baseline' ) );
	}

	public function handle_cleanup() {
		$this->require_admin_nonce( 'aio_ps_cleanup' );
		if ( ! current_user_can( 'delete_plugins' ) || ! current_user_can( 'delete_users' ) ) {
			wp_die( esc_html__( 'You are not allowed to run incident cleanup.', 'aio-plugin-sentinel' ) );
		}
		$cleanup = $this->scanner->quarantine_confirmed_findings();
		$removed_users = $this->remove_unapproved_administrators();
		$this->write_cleanup_log( $cleanup, $removed_users );
		$notice = empty( $cleanup['actions'] ) && empty( $removed_users ) ? 'nothing_to_clean' : 'cleaned';
		$this->redirect( array( 'aio_ps_notice' => $notice ) );
	}

	public function handle_settings() {
		$this->require_admin_nonce( 'aio_ps_settings' );
		$intervals = array( 'aio_ps_15_minutes', 'hourly', 'twicedaily', 'daily' );
		$interval = isset( $_POST['scan_interval'] ) ? sanitize_key( wp_unslash( $_POST['scan_interval'] ) ) : 'hourly';
		$settings = array(
			'change_lock' => ! empty( $_POST['change_lock'] ),
			'scan_interval' => in_array( $interval, $intervals, true ) ? $interval : 'hourly',
			'notification_recipients' => $this->sanitize_recipients( isset( $_POST['notification_recipients'] ) ? wp_unslash( $_POST['notification_recipients'] ) : '' ),
			'auto_quarantine_known' => ! empty( $_POST['auto_quarantine_known'] ),
			'approved_admins' => $this->sanitize_approved_admins( isset( $_POST['approved_admins'] ) ? wp_unslash( $_POST['approved_admins'] ) : '' ),
			'cleanup_unapproved_admins' => ! empty( $_POST['cleanup_unapproved_admins'] ),
			'enforce_plugin_approval' => ! empty( $_POST['enforce_plugin_approval'] ),
			'external_monitor' => ! empty( $_POST['external_monitor'] ),
			'monitor_urls' => AIO_PS_Monitor::sanitize_monitor_urls( isset( $_POST['monitor_urls'] ) ? wp_unslash( $_POST['monitor_urls'] ) : '' ),
			'delete_data_on_uninstall' => ! empty( $_POST['delete_data_on_uninstall'] ),
		);
		update_option( self::OPTION_SETTINGS, $settings, false );
		self::reschedule_scans();
		$this->redirect( array( 'aio_ps_notice' => 'settings' ) );
	}

	public function handle_install_guard() {
		$this->require_admin_nonce( 'aio_ps_install_guard' );
		$status = self::install_mu_guard();
		$this->redirect( array( empty( $status['verified'] ) ? 'aio_ps_error' : 'aio_ps_notice' => rawurlencode( $status['message'] ) ) );
	}

	/**
	 * Send a harmless preview of the calm, no-infection notification design.
	 */
	public function handle_test_email() {
		$this->require_admin_nonce( 'aio_ps_test_email' );

		$sent = $this->send_notification(
			__( 'Test email: no infection found', 'aio-plugin-sentinel' ),
			array(
				__( 'This is a test of the AIO Plugin Sentinel security-notification email.', 'aio-plugin-sentinel' ),
				__( 'No infection, reinfection, or required action is associated with this test.', 'aio-plugin-sentinel' ),
			),
			'clear',
			current_time( 'mysql', true )
		);

		$this->redirect(
			array(
				$sent ? 'aio_ps_notice' : 'aio_ps_error' => $sent
					? 'test_email_sent'
					: rawurlencode( __( 'WordPress could not send the test email. Check the site mail configuration.', 'aio-plugin-sentinel' ) ),
			)
		);
	}

	public function handle_download_guard() {
		$this->require_admin_nonce( 'aio_ps_download_guard' );
		$source = self::guard_source_path();
		if ( ! is_readable( $source ) ) {
			wp_die( esc_html__( 'The bundled MU guard file is unavailable.', 'aio-plugin-sentinel' ) );
		}
		nocache_headers();
		header( 'Content-Type: application/octet-stream' );
		header( 'Content-Disposition: attachment; filename="' . self::GUARD_FILENAME . '"' );
		header( 'Content-Length: ' . (string) filesize( $source ) );
		readfile( $source );
		exit;
	}

	public function handle_approve_inventory() {
		$this->require_admin_nonce( 'aio_ps_approve_inventory' );
		if ( empty( $_POST['aio_ps_acknowledge_inventory'] ) ) {
			$this->redirect( array( 'aio_ps_error' => rawurlencode( __( 'Confirm that you reviewed the full plugin directories before approving the inventory.', 'aio-plugin-sentinel' ) ) ) );
		}
		$results = $this->scanner->scan();
		$critical = array_filter( $results['findings'], function( $finding ) {
			return isset( $finding['severity'] ) && 'critical' === $finding['severity'];
		} );
		if ( ! empty( $critical ) ) {
			$this->redirect( array( 'aio_ps_error' => rawurlencode( __( 'The inventory was not approved because the fresh scan found critical findings. Review or quarantine those findings first.', 'aio-plugin-sentinel' ) ) ) );
		}
		$count = AIO_PS_Monitor::approve_current_inventory();
		$this->redirect( array( 'aio_ps_notice' => 'inventory_approved', 'aio_ps_count' => $count ) );
	}

	public function handle_export_evidence() {
		$this->require_admin_nonce( 'aio_ps_export_evidence' );
		$report = array(
			'generated_at' => current_time( 'mysql', true ),
			'site_url' => home_url( '/' ),
			'plugin_version' => AIO_PS_VERSION,
			'latest_scan' => $this->scanner->latest_results(),
			'health' => AIO_PS_Monitor::latest_health(),
			'external_monitor' => AIO_PS_Monitor::latest_external(),
			'update_exposure' => AIO_PS_Monitor::update_exposure(),
			'plugin_inventory' => AIO_PS_Monitor::plugin_inventory(),
			'cleanup_audit_log' => get_option( self::OPTION_CLEANUP_LOG, array() ),
		);
		nocache_headers();
		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="aio-plugin-sentinel-evidence-' . gmdate( 'Ymd-His' ) . '.json"' );
		echo wp_json_encode( $report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES );
		exit;
	}

	public function handle_restore_quarantine() {
		$this->require_admin_nonce( 'aio_ps_restore_quarantine' );
		if ( ! current_user_can( 'delete_plugins' ) ) {
			wp_die( esc_html__( 'You are not allowed to restore quarantined code.', 'aio-plugin-sentinel' ) );
		}
		$token = isset( $_POST['aio_ps_quarantine_token'] ) ? sanitize_text_field( wp_unslash( $_POST['aio_ps_quarantine_token'] ) ) : '';
		$result = $this->scanner->restore_quarantined( $token );
		$this->redirect( is_wp_error( $result ) ? array( 'aio_ps_error' => rawurlencode( $result->get_error_message() ) ) : array( 'aio_ps_notice' => 'restored' ) );
	}

	public function run_scheduled_scan() {
		$results = $this->run_monitoring_cycle();
		$settings = $this->settings();
		if ( ! empty( $settings['auto_quarantine_known'] ) ) {
			$cleanup = $this->scanner->quarantine_confirmed_findings( true );
			if ( ! empty( $cleanup['actions'] ) || ! empty( $cleanup['errors'] ) ) {
				$this->write_cleanup_log( $cleanup, array() );
				$this->send_notification( __( 'Automatic containment completed', 'aio-plugin-sentinel' ), array_merge( $cleanup['actions'], $cleanup['errors'] ), 'urgent', current_time( 'mysql', true ) );
			}
		}
	}

	public function run_post_update_scan() {
		$this->run_monitoring_cycle();
	}

	public function record_health() {
		if ( current_user_can( 'activate_plugins' ) ) {
			AIO_PS_Monitor::health( $this->settings(), $this->scanner->latest_results() );
		}
	}

	private function run_monitoring_cycle() {
		$results = $this->scanner->scan();
		$external = AIO_PS_Monitor::run_external_checks( $this->settings() );
		$health = AIO_PS_Monitor::health( $this->settings(), $results );
		$this->notify_if_actionable( $results, $health, $external );
		return $results;
	}

	public function block_activation( $new_value, $old_value ) {
		$requested = array_diff( (array) $new_value, (array) $old_value );
		$settings = $this->settings();
		$blocked = array_filter( $requested, function( $plugin ) use ( $settings ) {
			if ( 'aio-plugin-sentinel/aio-plugin-sentinel.php' === $plugin ) {
				return false;
			}
			return $this->scanner->is_plugin_file_blocked( $plugin ) || ! empty( $settings['change_lock'] ) || ( ! empty( $settings['enforce_plugin_approval'] ) && ! AIO_PS_Monitor::is_plugin_approved( $plugin ) );
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
		set_transient( 'aio_ps_activation_blocked', implode( ', ', $blocked ), MINUTE_IN_SECONDS );
		return array_values( $new_value );
	}

	public function check_upgrade_source( $response, $hook_extra ) {
		if ( empty( $hook_extra['plugin'] ) ) {
			return $response;
		}
		if ( $this->scanner->is_plugin_file_blocked( $hook_extra['plugin'] ) ) {
			return new WP_Error( 'aio_ps_upgrade_blocked', __( 'AIO Plugin Sentinel blocked an update for a known malicious plugin identifier.', 'aio-plugin-sentinel' ) );
		}
		if ( ! empty( $this->settings()['change_lock'] ) ) {
			return new WP_Error( 'aio_ps_lockdown_blocked', __( 'AIO Plugin Sentinel change lock is enabled. Disable it temporarily to approve this plugin update.', 'aio-plugin-sentinel' ) );
		}
		if ( ! empty( $this->settings()['enforce_plugin_approval'] ) && ! AIO_PS_Monitor::is_plugin_approved( $hook_extra['plugin'] ) ) {
			return new WP_Error( 'aio_ps_unapproved_upgrade', __( 'This plugin is not in the approved inventory. Review the plugin and capture the current inventory before updating it.', 'aio-plugin-sentinel' ) );
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
		$health = AIO_PS_Monitor::health( $settings, $results );
		$external = AIO_PS_Monitor::latest_external();
		$inventory = AIO_PS_Monitor::plugin_inventory();
		$update_exposure = AIO_PS_Monitor::update_exposure();
		?>
		<div class="wrap">
			<div class="aio-ps-brand">
				<a class="aio-ps-brand-logo" href="https://aiowebdesigns.com/" target="_blank" rel="noopener noreferrer">
					<img src="<?php echo esc_url( AIO_PS_URL . 'assets/aio-logo.png' ); ?>" alt="<?php esc_attr_e( 'AIO Web Designs', 'aio-plugin-sentinel' ); ?>" />
				</a>
				<div>
					<h1><?php esc_html_e( 'AIO Plugin Sentinel', 'aio-plugin-sentinel' ); ?></h1>
					<p><?php esc_html_e( 'Scheduled detection and controlled incident response for plugins, must-use plugins, drop-ins, and executable uploads.', 'aio-plugin-sentinel' ); ?></p>
					<p class="aio-ps-brand-link"><a href="https://aiowebdesigns.com/" target="_blank" rel="noopener noreferrer">aiowebdesigns.com</a></p>
				</div>
			</div>
			<p class="aio-ps-update-note"><?php esc_html_e( 'Plugin updates retain this site\'s monitoring settings, notification recipients, approved administrators, baseline, scan history, and cleanup audit log.', 'aio-plugin-sentinel' ); ?></p>
			<?php $this->render_notices(); ?>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline-block;margin-right:8px"><input type="hidden" name="action" value="aio_ps_scan" /><?php wp_nonce_field( 'aio_ps_scan' ); ?><?php submit_button( __( 'Run Security Scan', 'aio-plugin-sentinel' ), 'primary', 'aio_ps_run_scan', false ); ?></form>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline-block"><input type="hidden" name="action" value="aio_ps_baseline" /><?php wp_nonce_field( 'aio_ps_baseline' ); ?><?php submit_button( empty( $baseline ) ? __( 'Create Clean Baseline', 'aio-plugin-sentinel' ) : __( 'Refresh Baseline', 'aio-plugin-sentinel' ), 'secondary', 'aio_ps_create_baseline', false ); ?></form>
			<?php $this->render_health( $health, $external ); ?>
			<?php $this->render_update_exposure( $update_exposure ); ?>
			<h2><?php esc_html_e( 'Scheduled Monitoring & Notifications', 'aio-plugin-sentinel' ); ?></h2>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="aio_ps_settings" /><?php wp_nonce_field( 'aio_ps_settings' ); ?>
				<table class="form-table" role="presentation"><tbody>
				<tr><th scope="row"><label for="aio-ps-interval"><?php esc_html_e( 'Scan interval', 'aio-plugin-sentinel' ); ?></label></th><td><select id="aio-ps-interval" name="scan_interval"><option value="aio_ps_15_minutes" <?php selected( $settings['scan_interval'], 'aio_ps_15_minutes' ); ?>><?php esc_html_e( 'Every 15 minutes', 'aio-plugin-sentinel' ); ?></option><option value="hourly" <?php selected( $settings['scan_interval'], 'hourly' ); ?>><?php esc_html_e( 'Hourly', 'aio-plugin-sentinel' ); ?></option><option value="twicedaily" <?php selected( $settings['scan_interval'], 'twicedaily' ); ?>><?php esc_html_e( 'Twice daily', 'aio-plugin-sentinel' ); ?></option><option value="daily" <?php selected( $settings['scan_interval'], 'daily' ); ?>><?php esc_html_e( 'Daily', 'aio-plugin-sentinel' ); ?></option></select><p class="description"><?php esc_html_e( 'WP-Cron runs when WordPress receives traffic. Configure a host scheduler to call wp-cron.php for exact timing.', 'aio-plugin-sentinel' ); ?></p></td></tr>
				<tr><th scope="row"><label for="aio-ps-recipients"><?php esc_html_e( 'Security notification emails', 'aio-plugin-sentinel' ); ?></label></th><td><textarea id="aio-ps-recipients" name="notification_recipients" rows="4" class="large-text" placeholder="security@example.com, owner@example.com"><?php echo esc_textarea( $settings['notification_recipients'] ); ?></textarea><p class="description"><?php esc_html_e( 'Comma, space, or line-separated. The WordPress site administrator email is always included.', 'aio-plugin-sentinel' ); ?></p></td></tr>
				<tr><th scope="row"><?php esc_html_e( 'Controls', 'aio-plugin-sentinel' ); ?></th><td><label><input type="checkbox" name="change_lock" value="1" <?php checked( ! empty( $settings['change_lock'] ) ); ?> /> <?php esc_html_e( 'Lock all new plugin activation and plugin updates until explicitly approved.', 'aio-plugin-sentinel' ); ?></label><br /><label><input type="checkbox" name="enforce_plugin_approval" value="1" <?php checked( ! empty( $settings['enforce_plugin_approval'] ) ); ?> /> <?php esc_html_e( 'Block activation of plugins not present in this site\'s approved-plugin inventory.', 'aio-plugin-sentinel' ); ?></label><br /><label><input type="checkbox" name="auto_quarantine_known" value="1" <?php checked( ! empty( $settings['auto_quarantine_known'] ) ); ?> /> <?php esc_html_e( 'Automatically quarantine only exact known-malicious plugin names after a scheduled scan.', 'aio-plugin-sentinel' ); ?></label><p class="description"><?php esc_html_e( 'Approval enforcement allows reviewed plugins to be updated, then flags their changed version or checksum for review. It does not replace controlled updates or server-level file restrictions.', 'aio-plugin-sentinel' ); ?></p></td></tr>
				<tr><th scope="row"><label for="aio-ps-monitor-urls"><?php esc_html_e( 'Public-page monitoring', 'aio-plugin-sentinel' ); ?></label></th><td><label><input type="checkbox" name="external_monitor" value="1" <?php checked( ! empty( $settings['external_monitor'] ) ); ?> /> <?php esc_html_e( 'Check the public homepage and the URLs below for fake verification patterns during each scan.', 'aio-plugin-sentinel' ); ?></label><textarea id="aio-ps-monitor-urls" name="monitor_urls" rows="4" class="large-text" placeholder="https://example.com/important-page/"><?php echo esc_textarea( $settings['monitor_urls'] ); ?></textarea><p class="description"><?php esc_html_e( 'Optional public URLs, one per line. The plugin stores only response status and matching indicator words, never the page content.', 'aio-plugin-sentinel' ); ?></p></td></tr>
				<tr><th scope="row"><label for="aio-ps-approved-admins"><?php esc_html_e( 'Approved administrator accounts', 'aio-plugin-sentinel' ); ?></label></th><td><textarea id="aio-ps-approved-admins" name="approved_admins" rows="4" class="large-text" placeholder="neil, neil@example.com"><?php echo esc_textarea( $settings['approved_admins'] ); ?></textarea><p class="description"><?php esc_html_e( 'Only listed login names or email addresses are approved for one-click administrator cleanup. Leave this blank to disable user removal.', 'aio-plugin-sentinel' ); ?></p><label><input type="checkbox" name="cleanup_unapproved_admins" value="1" <?php checked( ! empty( $settings['cleanup_unapproved_admins'] ) ); ?> /> <?php esc_html_e( 'Permit one-click cleanup to remove unapproved administrator accounts, except the current user and all Super Admins.', 'aio-plugin-sentinel' ); ?></label></td></tr>
				<tr><th scope="row"><?php esc_html_e( 'Data retention', 'aio-plugin-sentinel' ); ?></th><td><label><input type="checkbox" name="delete_data_on_uninstall" value="1" <?php checked( ! empty( $settings['delete_data_on_uninstall'] ) ); ?> /> <?php esc_html_e( 'Delete Plugin Sentinel settings, scan records, baseline, approval ledger, health data, and audit log when the plugin is uninstalled.', 'aio-plugin-sentinel' ); ?></label><p class="description"><?php esc_html_e( 'Off by default. Quarantined files and the standalone MU guard are never removed automatically, so a protective record remains available for review.', 'aio-plugin-sentinel' ); ?></p></td></tr>
				</tbody></table>
				<?php submit_button( __( 'Save Monitoring Settings', 'aio-plugin-sentinel' ), 'primary', 'aio_ps_save_settings' ); ?>
			</form>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top: 10px;">
				<input type="hidden" name="action" value="aio_ps_test_email" />
				<?php wp_nonce_field( 'aio_ps_test_email' ); ?>
				<?php submit_button( __( 'Send Branded Test Email', 'aio-plugin-sentinel' ), 'secondary', 'aio_ps_send_test_email', false ); ?>
				<p class="description"><?php esc_html_e( 'Sends the calm, no-infection email layout to the site administrator and configured security recipients. It does not run a scan or change any settings.', 'aio-plugin-sentinel' ); ?></p>
			</form>
			<h2><?php esc_html_e( 'Approved Plugin Inventory', 'aio-plugin-sentinel' ); ?></h2>
			<p><?php esc_html_e( 'Capture this inventory only after reviewing installed plugins and their updates. Approval records the version, main-file checksum, and a deterministic fingerprint of every regular file inside each plugin directory. It does not approve a publisher or guarantee safety.', 'aio-plugin-sentinel' ); ?></p>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"><input type="hidden" name="action" value="aio_ps_approve_inventory" /><?php wp_nonce_field( 'aio_ps_approve_inventory' ); ?><label><input type="checkbox" name="aio_ps_acknowledge_inventory" value="1" required="required" /> <?php esc_html_e( 'I reviewed the current plugin directories and understand that this approval records their present state for this website.', 'aio-plugin-sentinel' ); ?></label><br /><?php submit_button( __( 'Approve Reviewed Plugin Inventory', 'aio-plugin-sentinel' ), 'secondary', 'aio_ps_approve_inventory_button', false, array( 'onclick' => "return confirm('A fresh scan will run. This approves the current full-directory fingerprints only when it has no critical findings. Continue?');" ) ); ?></form>
			<?php $this->render_inventory( $inventory, $settings ); ?>
			<h2><?php esc_html_e( 'One-Click Incident Cleanup', 'aio-plugin-sentinel' ); ?></h2>
			<p><?php esc_html_e( 'Fresh-scans the site, quarantines critical findings from active locations, and optionally removes explicitly unapproved administrator accounts. Quarantined files are preserved for review.', 'aio-plugin-sentinel' ); ?></p>
			<p class="description"><?php esc_html_e( 'False-positive workflow: export the evidence, review the file and its publisher, and use Restore Without Activating only after a qualified reviewer documents why the finding is safe. Review-level findings are never quarantined automatically.', 'aio-plugin-sentinel' ); ?></p>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"><input type="hidden" name="action" value="aio_ps_cleanup" /><?php wp_nonce_field( 'aio_ps_cleanup' ); ?><?php submit_button( __( 'Run Incident Cleanup', 'aio-plugin-sentinel' ), 'delete', 'aio_ps_run_cleanup', false, array( 'onclick' => "return confirm('This will quarantine all critical malware findings and may remove unapproved administrator accounts if that setting is enabled. Continue?');" ) ); ?></form>
			<p><strong><?php esc_html_e( 'Stronger server-level lock:', 'aio-plugin-sentinel' ); ?></strong> <code>define( 'DISALLOW_FILE_MODS', true );</code> <?php esc_html_e( 'in wp-config.php disables dashboard plugin/theme installation, updates, and edits.', 'aio-plugin-sentinel' ); ?></p>
			<?php $guard = self::guard_status(); ?>
			<h2><?php esc_html_e( 'Early-Boot MU Guard', 'aio-plugin-sentinel' ); ?></h2>
			<?php if ( $guard['verified'] ) : ?>
				<p><strong><?php esc_html_e( 'Installed and verified.', 'aio-plugin-sentinel' ); ?></strong> <?php esc_html_e( 'The guard loads before ordinary plugins and prevents known malicious plugin identifiers from being activated.', 'aio-plugin-sentinel' ); ?></p>
			<?php else : ?>
				<p><strong><?php esc_html_e( 'Not verified.', 'aio-plugin-sentinel' ); ?></strong> <?php echo esc_html( isset( $guard['last_attempt']['message'] ) ? $guard['last_attempt']['message'] : __( 'The guard has not yet been installed.', 'aio-plugin-sentinel' ) ); ?></p>
			<?php endif; ?>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline-block;margin-right:8px"><input type="hidden" name="action" value="aio_ps_install_guard" /><?php wp_nonce_field( 'aio_ps_install_guard' ); ?><?php submit_button( __( 'Install or Repair MU Guard', 'aio-plugin-sentinel' ), 'secondary', 'aio_ps_install_guard_button', false ); ?></form>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline-block"><input type="hidden" name="action" value="aio_ps_download_guard" /><?php wp_nonce_field( 'aio_ps_download_guard' ); ?><?php submit_button( __( 'Download MU Guard', 'aio-plugin-sentinel' ), 'secondary', 'aio_ps_download_guard_button', false ); ?></form>
			<p class="description"><?php esc_html_e( 'Expected target:', 'aio-plugin-sentinel' ); ?> <code><?php echo esc_html( $guard['target'] ); ?></code>. <?php esc_html_e( 'If automated installation is blocked by hosting permissions, upload the downloaded file to that exact location.', 'aio-plugin-sentinel' ); ?></p>
			<?php $this->render_results( $results ); ?>
			<?php $this->render_quarantine_restore(); ?>
			<h2><?php esc_html_e( 'Security Evidence', 'aio-plugin-sentinel' ); ?></h2>
			<p><?php esc_html_e( 'Download a JSON evidence report containing scan results, integrity changes, health checks, public-page results, plugin inventory, and cleanup history. Keep it with the incident ticket or client record.', 'aio-plugin-sentinel' ); ?></p>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"><input type="hidden" name="action" value="aio_ps_export_evidence" /><?php wp_nonce_field( 'aio_ps_export_evidence' ); ?><?php submit_button( __( 'Download Security Evidence', 'aio-plugin-sentinel' ), 'secondary', 'aio_ps_export_evidence_button', false ); ?></form>
			<?php $this->render_cleanup_log(); ?>
		</div>
		<?php
	}

	private function notify_if_actionable( $results, $health = array(), $external = array() ) {
		$critical = array_values( array_filter( $results['findings'], function( $finding ) { return 'critical' === $finding['severity']; } ) );
		$integrity = isset( $results['integrity'] ) ? $results['integrity'] : array();
		$changed = ! empty( $integrity['added'] ) || ! empty( $integrity['modified'] ) || ! empty( $integrity['removed'] );
		$health_issues = isset( $health['issues'] ) ? $health['issues'] : array();
		$suspicious_pages = AIO_PS_Monitor::suspicious_external_checks( $external );
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
			$this->send_notification( __( 'Action required: security finding detected', 'aio-plugin-sentinel' ), $details, 'urgent', $results['scanned_at'] );
		} elseif ( ! empty( $health_issues ) ) {
			$this->send_notification( __( 'Monitoring attention recommended: no infection found', 'aio-plugin-sentinel' ), $details, 'attention', $results['scanned_at'] );
		} else {
			$this->send_notification( __( 'Security check complete: no infection found', 'aio-plugin-sentinel' ), $details, 'clear', $results['scanned_at'] );
		}
		update_option( self::OPTION_ALERT, $fingerprint, false );
	}

	private function send_notification( $subject, $lines, $state = 'urgent', $scanned_at = '' ) {
		$recipients = $this->notification_recipients();
		if ( ! empty( $recipients ) ) {
			return wp_mail( $recipients, '[AIO Plugin Sentinel] ' . $subject, $this->notification_email( $lines, $state, $scanned_at ), array( 'Content-Type: text/html; charset=UTF-8' ) );
		}

		return false;
	}

	private function notification_email( $details, $state, $scanned_at ) {
		$copy = array(
			'urgent' => array(
				'eyebrow' => __( 'Security attention needed', 'aio-plugin-sentinel' ),
				'headline' => __( 'A security issue needs review', 'aio-plugin-sentinel' ),
				'intro' => __( 'Plugin Sentinel identified a critical malware indicator, a fake-verification pattern, or a failed protection layer.', 'aio-plugin-sentinel' ),
				'action' => __( 'Please have an authorized administrator review Plugin Sentinel as soon as possible.', 'aio-plugin-sentinel' ),
				'color' => '#b42318',
				'background' => '#fef3f2',
			),
			'attention' => array(
				'eyebrow' => __( 'Monitoring status update', 'aio-plugin-sentinel' ),
				'headline' => __( 'No known infection was found', 'aio-plugin-sentinel' ),
				'intro' => __( 'The scan did not find a known x-dav or fake-verification infection. A monitoring condition should be reviewed by the site administrator or AIO technical team.', 'aio-plugin-sentinel' ),
				'action' => __( 'No emergency response is indicated, but please review the monitoring note below.', 'aio-plugin-sentinel' ),
				'color' => '#9a6700',
				'background' => '#fffaeb',
			),
			'clear' => array(
				'eyebrow' => __( 'Security monitoring update', 'aio-plugin-sentinel' ),
				'headline' => __( 'No infection or reinfection found', 'aio-plugin-sentinel' ),
				'intro' => __( 'Plugin Sentinel did not identify a known x-dav, fake-verification, or other critical malware indicator during this scan.', 'aio-plugin-sentinel' ),
				'action' => __( 'No immediate action is required from you. A recorded file change is included below for AIO technical records and does not mean an infection was found.', 'aio-plugin-sentinel' ),
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
			$items = '<li style="margin:0;line-height:1.5;color:#344054">' . esc_html__( 'No additional scan details were recorded.', 'aio-plugin-sentinel' ) . '</li>';
		}
		$tools_url = admin_url( 'tools.php?page=aio-plugin-sentinel' );
		return '<!doctype html><html><body style="margin:0;padding:0;background:#f2f4f7;font-family:Arial,sans-serif;color:#101828"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f2f4f7;padding:28px 12px"><tr><td align="center"><table role="presentation" width="600" cellspacing="0" cellpadding="0" style="max-width:600px;width:100%;background:#ffffff;border-radius:8px;overflow:hidden"><tr><td align="center" style="padding:30px 24px 18px"><img src="' . esc_url( AIO_PS_URL . 'assets/aio-logo.png' ) . '" width="150" alt="AIO Web Designs" style="display:block;border:0;max-width:150px;height:auto" /></td></tr><tr><td style="padding:0 32px 30px"><p style="margin:0 0 8px;color:#1ca4df;font-size:13px;font-weight:bold;letter-spacing:.8px;text-transform:uppercase">' . esc_html( $copy['eyebrow'] ) . '</p><h1 style="margin:0 0 14px;font-size:26px;line-height:1.25;color:#101828">' . esc_html( $copy['headline'] ) . '</h1><p style="margin:0 0 18px;font-size:16px;line-height:1.55;color:#344054">' . esc_html( $copy['intro'] ) . '</p><div style="margin:0 0 22px;padding:14px 16px;background:' . esc_attr( $copy['background'] ) . ';border-left:4px solid ' . esc_attr( $copy['color'] ) . ';color:#101828;font-size:15px;line-height:1.5"><strong>' . esc_html( $copy['action'] ) . '</strong></div><h2 style="margin:0 0 10px;font-size:16px;color:#101828">' . esc_html__( 'Scan details', 'aio-plugin-sentinel' ) . '</h2><ul style="margin:0 0 20px;padding-left:20px">' . $items . '</ul><p style="margin:0;font-size:13px;line-height:1.5;color:#667085">' . esc_html( sprintf( __( 'Scan completed: %s UTC.', 'aio-plugin-sentinel' ), $scanned_at ) ) . ' <a href="' . esc_url( $tools_url ) . '" style="color:#087db8;text-decoration:underline">' . esc_html__( 'Open AIO Plugin Sentinel', 'aio-plugin-sentinel' ) . '</a></p></td></tr><tr><td align="center" style="padding:18px 24px;background:#f9fafb;border-top:1px solid #eaecf0;font-size:12px;line-height:1.5;color:#667085">AIO Plugin Sentinel by <a href="https://aiowebdesigns.com/" style="color:#087db8;text-decoration:underline">AIO Web Designs</a></td></tr></table></td></tr></table></body></html>';
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
		if ( isset( $_GET['aio_ps_notice'] ) ) {
			$messages = array( 'scanned' => __( 'Security scan completed.', 'aio-plugin-sentinel' ), 'baseline' => __( 'Clean baseline saved.', 'aio-plugin-sentinel' ), 'settings' => __( 'Monitoring settings saved.', 'aio-plugin-sentinel' ), 'test_email_sent' => __( 'Branded test email sent to the site administrator and configured security recipients.', 'aio-plugin-sentinel' ), 'cleaned' => __( 'Incident cleanup completed. Review the cleanup log below.', 'aio-plugin-sentinel' ), 'nothing_to_clean' => __( 'No critical finding or unapproved approved-list administrator required cleanup.', 'aio-plugin-sentinel' ), 'inventory_approved' => __( 'The current plugin inventory was recorded as approved.', 'aio-plugin-sentinel' ), 'restored' => __( 'The quarantined item was restored but was not activated.', 'aio-plugin-sentinel' ) );
			echo '<div class="notice notice-success"><p>' . esc_html( isset( $messages[ $_GET['aio_ps_notice'] ] ) ? $messages[ $_GET['aio_ps_notice'] ] : __( 'Action completed.', 'aio-plugin-sentinel' ) ) . '</p></div>';
		}
		if ( isset( $_GET['aio_ps_error'] ) ) { echo '<div class="notice notice-error"><p>' . esc_html( rawurldecode( wp_unslash( $_GET['aio_ps_error'] ) ) ) . '</p></div>'; }
		if ( $blocked = get_transient( 'aio_ps_activation_blocked' ) ) { echo '<div class="notice notice-error"><p>' . esc_html__( 'Blocked plugin activation: ', 'aio-plugin-sentinel' ) . esc_html( $blocked ) . '</p></div>'; }
	}

	private function render_health( $health, $external ) {
		echo '<h2>' . esc_html__( 'Protection Health', 'aio-plugin-sentinel' ) . '</h2>';
		$issues = isset( $health['issues'] ) ? $health['issues'] : array();
		if ( empty( $issues ) ) {
			echo '<p><strong>' . esc_html__( 'Guard, scan schedule, and scan freshness checks are healthy.', 'aio-plugin-sentinel' ) . '</strong></p>';
		} else {
			echo '<ul>';
			foreach ( $issues as $issue ) {
				echo '<li><strong>' . esc_html( ucfirst( $issue['severity'] ) ) . '</strong>: ' . esc_html( $issue['message'] ) . '</li>';
			}
			echo '</ul>';
		}
		if ( ! empty( $health['next_scan'] ) ) {
			echo '<p>' . sprintf( esc_html__( 'Next scheduled scan (UTC): %s.', 'aio-plugin-sentinel' ), esc_html( $health['next_scan'] ) ) . '</p>';
		}
		if ( empty( $external['enabled'] ) ) {
			echo '<p class="description">' . esc_html__( 'Public-page monitoring is currently off.', 'aio-plugin-sentinel' ) . '</p>';
		} elseif ( empty( $external['checks'] ) ) {
			echo '<p class="description">' . esc_html__( 'Public-page monitoring is enabled and will run with the next scan.', 'aio-plugin-sentinel' ) . '</p>';
		} else {
			$suspicious = AIO_PS_Monitor::suspicious_external_checks( $external );
			echo '<p><strong>' . ( empty( $suspicious ) ? esc_html__( 'Public-page check: no fake-verification pattern detected.', 'aio-plugin-sentinel' ) : esc_html__( 'Public-page check: suspected fake-verification pattern detected.', 'aio-plugin-sentinel' ) ) . '</strong></p>';
			if ( ! empty( $suspicious ) ) {
				echo '<ul>';
				foreach ( $suspicious as $check ) { echo '<li><code>' . esc_html( $check['url'] ) . '</code> (' . esc_html( implode( ', ', $check['markers'] ) ) . ')</li>'; }
				echo '</ul>';
			}
		}
	}

	private function render_inventory( $inventory, $settings ) {
		if ( empty( $inventory ) ) {
			echo '<p>' . esc_html__( 'No standard plugins were found.', 'aio-plugin-sentinel' ) . '</p>';
			return;
		}
		echo '<table class="widefat striped aio-ps-inventory"><thead><tr><th>' . esc_html__( 'Plugin', 'aio-plugin-sentinel' ) . '</th><th>' . esc_html__( 'Version', 'aio-plugin-sentinel' ) . '</th><th>' . esc_html__( 'State', 'aio-plugin-sentinel' ) . '</th><th>' . esc_html__( 'Directory Integrity', 'aio-plugin-sentinel' ) . '</th><th>' . esc_html__( 'Approval', 'aio-plugin-sentinel' ) . '</th></tr></thead><tbody>';
		foreach ( $inventory as $plugin ) {
			$state = $plugin['active'] ? __( 'Active', 'aio-plugin-sentinel' ) : __( 'Inactive', 'aio-plugin-sentinel' );
			$approval = $plugin['approved'] ? __( 'Approved full-directory match', 'aio-plugin-sentinel' ) : __( 'Review required', 'aio-plugin-sentinel' );
			$integrity = $plugin['directory_complete'] ? sprintf( _n( '%d file fingerprinted', '%d files fingerprinted', $plugin['directory_file_count'], 'aio-plugin-sentinel' ), $plugin['directory_file_count'] ) : __( 'Incomplete fingerprint - review required', 'aio-plugin-sentinel' );
			$approved_meta = $plugin['approved'] && $plugin['approved_at'] ? sprintf( __( '%1$s by %2$s', 'aio-plugin-sentinel' ), $plugin['approved_at'], $plugin['approved_by'] ? $plugin['approved_by'] : __( 'an administrator', 'aio-plugin-sentinel' ) ) : '';
			echo '<tr><td><code>' . esc_html( $plugin['file'] ) . '</code><br />' . esc_html( $plugin['name'] ) . '</td><td>' . esc_html( $plugin['version'] ) . '</td><td>' . esc_html( $state ) . '</td><td>' . esc_html( $integrity ) . '</td><td>' . esc_html( $approval ) . ( $approved_meta ? '<br /><span class="description">' . esc_html( $approved_meta ) . '</span>' : '' ) . '</td></tr>';
		}
		echo '</tbody></table>';
		if ( ! empty( $settings['enforce_plugin_approval'] ) ) {
			echo '<p class="description">' . esc_html__( 'Approval enforcement is enabled. New or changed plugin files remain visible here for review.', 'aio-plugin-sentinel' ) . '</p>';
		}
	}

	private function render_update_exposure( $exposure ) {
		$plugin_count = count( isset( $exposure['plugin_updates'] ) ? $exposure['plugin_updates'] : array() );
		echo '<h2>' . esc_html__( 'Update Exposure', 'aio-plugin-sentinel' ) . '</h2>';
		if ( empty( $exposure['core_update_available'] ) && ! $plugin_count ) {
			echo '<p><strong>' . esc_html__( 'WordPress currently reports no core or plugin updates.', 'aio-plugin-sentinel' ) . '</strong></p>';
		} else {
			echo '<p>' . sprintf( esc_html__( 'WordPress reports %1$d core update(s) and %2$d plugin update(s). Review releases before approving and installing them.', 'aio-plugin-sentinel' ), ! empty( $exposure['core_update_available'] ) ? 1 : 0, $plugin_count ) . '</p>';
			if ( $plugin_count ) {
				echo '<ul>';
				foreach ( $exposure['plugin_updates'] as $plugin_file ) { echo '<li><code>' . esc_html( $plugin_file ) . '</code></li>'; }
				echo '</ul>';
			}
		}
		echo '<p class="description">' . esc_html__( 'Update availability is not a vulnerability verdict. Plugin Sentinel does not claim to provide a live vulnerability intelligence feed.', 'aio-plugin-sentinel' ) . '</p>';
	}

	private function render_quarantine_restore() {
		$entries = $this->scanner->quarantine_entries();
		if ( empty( $entries ) ) {
			return;
		}
		echo '<h2>' . esc_html__( 'Quarantine Recovery', 'aio-plugin-sentinel' ) . '</h2><p>' . esc_html__( 'A restore only moves the selected item back to its original location. It does not activate a restored plugin. Restore only after a qualified review confirms the finding was a false positive.', 'aio-plugin-sentinel' ) . '</p>';
		echo '<table class="widefat striped"><thead><tr><th>' . esc_html__( 'Quarantined (UTC)', 'aio-plugin-sentinel' ) . '</th><th>' . esc_html__( 'Original location', 'aio-plugin-sentinel' ) . '</th><th>' . esc_html__( 'Action', 'aio-plugin-sentinel' ) . '</th></tr></thead><tbody>';
		foreach ( $entries as $entry ) {
			echo '<tr><td>' . esc_html( $entry['time'] ) . '</td><td><code>' . esc_html( $entry['source_path'] ) . '</code></td><td><form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="aio_ps_restore_quarantine" /><input type="hidden" name="aio_ps_quarantine_token" value="' . esc_attr( $entry['token'] ) . '" />' . wp_nonce_field( 'aio_ps_restore_quarantine', '_wpnonce', true, false ) . '<input type="submit" class="button" value="' . esc_attr__( 'Restore Without Activating', 'aio-plugin-sentinel' ) . '" onclick="return confirm(\'This will return the quarantined code to its original location without activating it. Continue only if the finding has been reviewed as a false positive.\');" /></form></td></tr>';
		}
		echo '</tbody></table>';
	}

	private function render_results( $results ) {
		echo '<h2>' . esc_html__( 'Latest Scan', 'aio-plugin-sentinel' ) . '</h2>';
		if ( empty( $results['scanned_at'] ) ) { echo '<p>' . esc_html__( 'No scan has run yet.', 'aio-plugin-sentinel' ) . '</p>'; return; }
		echo '<p>' . sprintf( esc_html__( 'Last scan (UTC): %1$s. Files reviewed: %2$d.', 'aio-plugin-sentinel' ), esc_html( $results['scanned_at'] ), (int) $results['file_count'] ) . '</p>';
		if ( empty( $results['findings'] ) ) { echo '<p><strong>' . esc_html__( 'No known x-dav indicators or high-risk code combinations were found.', 'aio-plugin-sentinel' ) . '</strong></p>'; }
		else { echo '<ul>'; foreach ( $results['findings'] as $finding ) { echo '<li><strong>' . esc_html( ucfirst( $finding['severity'] ) ) . '</strong>: <code>' . esc_html( $finding['file'] ) . '</code> (' . esc_html( implode( ', ', $finding['markers'] ) ?: __( 'known malicious directory name', 'aio-plugin-sentinel' ) ) . ')</li>'; } echo '</ul>'; }
		$integrity = isset( $results['integrity'] ) ? $results['integrity'] : array();
		if ( ! empty( $integrity['available'] ) ) { echo '<p>' . sprintf( esc_html__( 'Baseline changes: %1$d added, %2$d modified, %3$d removed.', 'aio-plugin-sentinel' ), count( $integrity['added'] ), count( $integrity['modified'] ), count( $integrity['removed'] ) ) . '</p>'; }
		else { echo '<p>' . esc_html__( 'No integrity baseline exists yet.', 'aio-plugin-sentinel' ) . '</p>'; }
	}

	private function render_cleanup_log() {
		$entries = get_option( self::OPTION_CLEANUP_LOG, array() );
		if ( empty( $entries ) ) { return; }
		echo '<h2>' . esc_html__( 'Cleanup Audit Log', 'aio-plugin-sentinel' ) . '</h2><table class="widefat striped"><thead><tr><th>' . esc_html__( 'Time (UTC)', 'aio-plugin-sentinel' ) . '</th><th>' . esc_html__( 'Quarantined', 'aio-plugin-sentinel' ) . '</th><th>' . esc_html__( 'Removed admins', 'aio-plugin-sentinel' ) . '</th><th>' . esc_html__( 'Errors', 'aio-plugin-sentinel' ) . '</th></tr></thead><tbody>';
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

	private function redirect( $args ) { wp_safe_redirect( add_query_arg( $args, admin_url( 'tools.php?page=aio-plugin-sentinel' ) ) ); exit; }

	private function require_admin_nonce( $action ) {
		if ( ! current_user_can( 'activate_plugins' ) ) { wp_die( esc_html__( 'You are not allowed to manage plugins.', 'aio-plugin-sentinel' ) ); }
		check_admin_referer( $action );
	}
}
