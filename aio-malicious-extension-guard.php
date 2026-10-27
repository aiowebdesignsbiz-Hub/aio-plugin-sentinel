<?php
/**
 * Plugin Name: AIO Malicious Extension Guard
 * Plugin URI: https://github.com/aiowebdesignsbiz-Hub/aio-plugin-sentinel
 * Description: Detects known malicious-plugin indicators, blocks unsafe plugin activation, and provides a controlled quarantine workflow.
 * Version: 5.6.0
 * Author: AIO Web Designs
 * Author URI: https://aiowebdesigns.com/
 * License: GPL-2.0-or-later
 * Text Domain: aio-malicious-extension-guard
 * Requires at least: 6.0
 * Requires PHP: 7.4
 */

defined( 'ABSPATH' ) || exit;

define( 'AIOMEG_VERSION', '5.6.0' );
define( 'AIOMEG_FILE', __FILE__ );
define( 'AIOMEG_DIR', plugin_dir_path( __FILE__ ) );
define( 'AIOMEG_URL', plugin_dir_url( __FILE__ ) );

require_once AIOMEG_DIR . 'includes/class-aiomeg-scanner.php';
require_once AIOMEG_DIR . 'includes/class-aiomeg-monitor.php';
require_once AIOMEG_DIR . 'includes/class-aiomeg-plugin.php';

register_activation_hook( __FILE__, array( 'AIOMEG_Plugin', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'AIOMEG_Plugin', 'deactivate' ) );

AIOMEG_Plugin::instance();
