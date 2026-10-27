<?php

class Test_AIOMEG_Directory_Integrity extends WP_UnitTestCase {
	private $directory;
	private $plugin_file = 'aiomeg-test-fixture/aiomeg-test-fixture.php';

	public function set_up() {
		parent::set_up();
		$this->directory = WP_PLUGIN_DIR . '/aiomeg-test-fixture';
		wp_mkdir_p( $this->directory . '/includes' );
		file_put_contents( $this->directory . '/aiomeg-test-fixture.php', "<?php\n/*\nPlugin Name: AIO PS Test Fixture\nVersion: 1.0.0\n*/\n" );
		file_put_contents( $this->directory . '/includes/helper.php', "<?php\nreturn 'clean';\n" );
		wp_clean_plugins_cache( true );
	}

	public function tear_down() {
		@unlink( $this->directory . '/includes/helper.php' );
		@rmdir( $this->directory . '/includes' );
		@unlink( $this->directory . '/aiomeg-test-fixture.php' );
		@rmdir( $this->directory );
		delete_option( AIOMEG_Monitor::OPTION_APPROVALS );
		wp_clean_plugins_cache( true );
		parent::tear_down();
	}

	public function test_directory_fingerprint_changes_when_a_non_main_file_changes() {
		$before = AIOMEG_Monitor::plugin_directory_fingerprint( $this->plugin_file );
		file_put_contents( $this->directory . '/includes/helper.php', "<?php\nreturn 'changed';\n" );
		$after = AIOMEG_Monitor::plugin_directory_fingerprint( $this->plugin_file );

		$this->assertTrue( $before['complete'] );
		$this->assertSame( 2, $before['file_count'] );
		$this->assertNotSame( $before['sha256'], $after['sha256'] );
	}

	public function test_approved_inventory_requires_the_full_directory_to_match() {
		AIOMEG_Monitor::approve_current_inventory();
		$inventory = AIOMEG_Monitor::plugin_inventory();
		$this->assertTrue( $inventory[ $this->plugin_file ]['approved'] );

		file_put_contents( $this->directory . '/includes/helper.php', "<?php\nreturn 'modified after approval';\n" );
		$inventory = AIOMEG_Monitor::plugin_inventory();
		$this->assertFalse( $inventory[ $this->plugin_file ]['approved'] );
	}

	public function test_individual_plugin_approval_can_be_revoked_without_changing_the_plugin() {
		$this->assertSame( 1, AIOMEG_Monitor::approve_plugins( array( $this->plugin_file ) ) );
		$inventory = AIOMEG_Monitor::plugin_inventory();
		$this->assertTrue( $inventory[ $this->plugin_file ]['approved'] );

		$this->assertSame( 1, AIOMEG_Monitor::revoke_plugin_approvals( array( $this->plugin_file ) ) );
		$inventory = AIOMEG_Monitor::plugin_inventory();
		$this->assertFalse( $inventory[ $this->plugin_file ]['approved'] );
		$this->assertFileExists( $this->directory . '/aiomeg-test-fixture.php' );
	}
}
