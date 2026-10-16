<?php
/**
 * Plugin Name: AIO Sentinel
 * Plugin URI: https://github.com/aiowebdesignsbiz-Hub/aio-plugin-sentinel
 * Description: Detects known malicious-plugin indicators, blocks unsafe plugin activation, and provides a controlled quarantine workflow.
 * Version: 5.3.2
 * Author: AIO Web Designs
 * Author URI: https://aiowebdesigns.com/
 * License: GPL-2.0-or-later
 * Text Domain: aio-sentinel
 * Requires at least: 6.0
 * Requires PHP: 7.4
 */

defined( 'ABSPATH' ) || exit;

define( 'AIO_PS_VERSION', '5.3.2' );
define( 'AIO_PS_FILE', __FILE__ );
define( 'AIO_PS_DIR', plugin_dir_path( __FILE__ ) );
define( 'AIO_PS_URL', plugin_dir_url( __FILE__ ) );
define( 'AIO_PS_GUARD_SHA256', 'C18B279E306D82E2A6558D011FFDB3C7E4AB663A186C8E138483EC612BA5F45E' );

require_once AIO_PS_DIR . 'includes/class-aio-ps-scanner.php';
require_once AIO_PS_DIR . 'includes/class-aio-ps-monitor.php';
require_once AIO_PS_DIR . 'includes/class-aio-ps-plugin.php';

register_activation_hook( __FILE__, array( 'AIO_PS_Plugin', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'AIO_PS_Plugin', 'deactivate' ) );

AIO_PS_Plugin::instance();
