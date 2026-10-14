<?php

class Test_AIO_PS_Settings_Migration extends WP_UnitTestCase {

	public function set_up() {
		parent::set_up();
		delete_option( AIO_PS_Plugin::OPTION_SETTINGS );
	}

	public function tear_down() {
		delete_option( AIO_PS_Plugin::OPTION_SETTINGS );
		parent::tear_down();
	}

	public function test_default_settings_are_safe_by_default() {
		$settings = AIO_PS_Plugin::default_settings();

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
		update_option( AIO_PS_Plugin::OPTION_SETTINGS, $stored, false );

		$method = new ReflectionMethod( 'AIO_PS_Plugin', 'migrate_settings' );
		$method->setAccessible( true );
		$method->invoke( null );

		$settings = get_option( AIO_PS_Plugin::OPTION_SETTINGS );
		$this->assertSame( 'daily', $settings['scan_interval'] );
		$this->assertSame( 'security@example.test', $settings['notification_recipients'] );
		$this->assertTrue( $settings['change_lock'] );
		$this->assertArrayHasKey( 'delete_data_on_uninstall', $settings );
		$this->assertFalse( $settings['delete_data_on_uninstall'] );
	}
}
