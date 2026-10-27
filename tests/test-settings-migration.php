<?php

class Test_AIOMEG_Settings_Migration extends WP_UnitTestCase {

	public function set_up() {
		parent::set_up();
		delete_option( AIOMEG_Plugin::OPTION_SETTINGS );
		delete_option( 'aio_ps_settings' );
		delete_option( 'aio_ps_scan_results' );
	}

	public function tear_down() {
		delete_option( AIOMEG_Plugin::OPTION_SETTINGS );
		delete_option( 'aio_ps_settings' );
		delete_option( 'aio_ps_scan_results' );
		delete_option( AIOMEG_Scanner::OPTION_RESULTS );
		parent::tear_down();
	}

	public function test_default_settings_are_safe_by_default() {
		$settings = AIOMEG_Plugin::default_settings();

		$this->assertFalse( $settings['change_lock'] );
		$this->assertFalse( $settings['auto_quarantine_known'] );
		$this->assertFalse( $settings['enforce_plugin_approval'] );
		$this->assertFalse( $settings['external_monitor'] );
		$this->assertFalse( $settings['delete_data_on_uninstall'] );
	}

	public function test_migration_preserves_existing_site_choices_and_adds_new_defaults() {
		$stored = array(
			'scan_interval'           => 'daily',
			'notification_recipients' => 'security@example.test',
			'change_lock'             => true,
		);
		update_option( AIOMEG_Plugin::OPTION_SETTINGS, $stored, false );

		$method = new ReflectionMethod( 'AIOMEG_Plugin', 'migrate_settings' );
		$method->setAccessible( true );
		$method->invoke( null );

		$settings = get_option( AIOMEG_Plugin::OPTION_SETTINGS );
		$this->assertSame( 'daily', $settings['scan_interval'] );
		$this->assertSame( 'security@example.test', $settings['notification_recipients'] );
		$this->assertTrue( $settings['change_lock'] );
		$this->assertArrayHasKey( 'delete_data_on_uninstall', $settings );
		$this->assertFalse( $settings['delete_data_on_uninstall'] );
	}

	public function test_legacy_data_is_imported_without_deleting_the_source_records() {
		$legacy_settings = array(
			'scan_interval'           => 'aio_ps_15_minutes',
			'notification_recipients' => 'security@example.test',
		);
		$legacy_results = array( 'scanned_at' => '2026-10-27 00:00:00', 'findings' => array(), 'integrity' => array(), 'file_count' => 25 );
		update_option( 'aio_ps_settings', $legacy_settings, false );
		update_option( 'aio_ps_scan_results', $legacy_results, false );

		$method = new ReflectionMethod( 'AIOMEG_Plugin', 'migrate_legacy_data' );
		$method->setAccessible( true );
		$method->invoke( null );

		$current_settings = get_option( AIOMEG_Plugin::OPTION_SETTINGS );
		$this->assertSame( 'aiomeg_15_minutes', $current_settings['scan_interval'] );
		$this->assertSame( 'security@example.test', $current_settings['notification_recipients'] );
		$this->assertSame( $legacy_results, get_option( AIOMEG_Scanner::OPTION_RESULTS ) );
		$this->assertSame( $legacy_settings, get_option( 'aio_ps_settings' ) );
	}
}
