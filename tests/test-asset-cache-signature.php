<?php

class Test_AIOMEG_Asset_Cache_Signature extends WP_UnitTestCase {
	public function test_verified_asset_cache_slug_is_blocked() {
		$scanner = new AIOMEG_Scanner();
		$this->assertTrue( $scanner->is_blocked_slug( 'asset-cache' ) );
		$this->assertTrue( $scanner->is_plugin_file_blocked( 'asset-cache/asset-cache.php' ) );
		$this->assertFalse( $scanner->is_blocked_slug( 'legitimate-cache-plugin' ) );
	}
}
