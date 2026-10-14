<?php
/**
 * Plugin Name: AIO Sentinel
 * Plugin URI: https://aiowebdesigns.com/
 * Description: Detects known malicious-plugin indicators, blocks unsafe plugin activation, and provides a controlled quarantine workflow.
 * Version: 5.3.1
 * Author: AIO Web Designs
 * Author URI: https://aiowebdesigns.com/
 * License: GPL-2.0-or-later
 * Text Domain: aio-sentinel
 * Requires at least: 6.0
 * Requires PHP: 7.4
 */

defined( 'ABSPATH' ) || exit;

define( 'AIO_PS_VERSION', '5.3.1' );
define( 'AIO_PS_FILE', __FILE__ );
define( 'AIO_PS_DIR', plugin_dir_path( __FILE__ ) );
define( 'AIO_PS_URL', plugin_dir_url( __FILE__ ) );
define( 'AIO_PS_GUARD_SHA256', '609D74BE0C7C36B78F00A534C99D4D08A71481347C4BDE008155F06AB7F46A80' );

require_once AIO_PS_DIR . 'includes/class-aio-ps-scanner.php';
require_once AIO_PS_DIR . 'includes/class-aio-ps-monitor.php';
require_once AIO_PS_DIR . 'includes/class-aio-ps-plugin.php';

register_activation_hook( __FILE__, array( 'AIO_PS_Plugin', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'AIO_PS_Plugin', 'deactivate' ) );

AIO_PS_Plugin::instance();
