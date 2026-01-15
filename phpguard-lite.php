<?php
/**
 * Plugin Name: PHPGuard Lite
 * Description: Check WordPress plugins and PHP code for syntax errors before activating or using them.
 * Version: 1.0.0
 * Author: M. Wouterse
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: phpguard-lite
 */


if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class PHPGuard_Preinstall_Plugin {

        const VERSION = '1.0.0';
    const OPTION_VERSION   = 'phpguard_preinstall_version';
    const OPTION_HISTORY   = 'phpguard_version_history';
    const OPTION_ACTIVATION_REDIRECT = 'phpguard_preinstall_activation_redirect';

    public function __construct() {
        // Lifecycle
        register_activation_hook( __FILE__, array( $this, 'on_activate' ) );
        add_action( 'plugins_loaded', array( $this, 'maybe_record_version_bump' ) );
        add_action( 'admin_init', array( $this, 'maybe_redirect_after_activation' ) );

        // Admin UI
        add_action( 'admin_menu', array( $this, 'register_menus' ) );

        // Ajax scan
        add_action( 'wp_ajax_phpguard_run_scan', array( $this, 'ajax_run_scan' ) );
        add_action( 'wp_ajax_phpguard_run_snippet_scan', array( $this, 'ajax_run_snippet_scan' ) );

        // Assets
        add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
    }

    public function on_activate() {
        $this->maybe_record_version_bump();
        // Flag for one-time redirect to the main PHPGuard screen after activation.
        update_option( self::OPTION_ACTIVATION_REDIRECT, true );
    }

    public function maybe_redirect_after_activation() {
        // Only run in admin for users who can manage options.
        if ( ! is_admin() || ! current_user_can( 'manage_options' ) ) {
            return;
        }

        // Only redirect once, immediately after activation.
        $flag = get_option( self::OPTION_ACTIVATION_REDIRECT );
        if ( ! $flag ) {
            return;
        }

        // Do not hijack bulk activations.
        if ( isset( $_GET['activate-multi'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            delete_option( self::OPTION_ACTIVATION_REDIRECT );
            return;
        }

        delete_option( self::OPTION_ACTIVATION_REDIRECT );

        wp_safe_redirect( admin_url( 'admin.php?page=phpguard-lite' ) );
        exit;
    }

    /**
     * Record a version bump into shared history option.
     */
    public function maybe_record_version_bump() {
        $stored = get_option( self::OPTION_VERSION );
        if ( $stored === self::VERSION ) {
            return;
        }

        update_option( self::OPTION_VERSION, self::VERSION );

        $history = get_option( self::OPTION_HISTORY );
        if ( ! is_array( $history ) ) {
            $history = array();
        }

        $notes = $this->get_version_notes( self::VERSION );

        $history[] = array(
            'component' => 'preinstall_free',
            'version'   => self::VERSION,
            'timestamp' => time(),
            'notes'     => $notes,
        );

        update_option( self::OPTION_HISTORY, $history );
    }

    /**
     * Notes for known versions.
     *
     * @param string $version Version string.
     * @return string
     */
    protected function get_version_notes( $version ) {
        switch ( $version ) {
            case '1.0.0':
                return __( 'Initial public release of PHPGuard Pre-Install Safety Checker.', 'phpguard-lite' );
        }
    }

    public function register_menus() {
        // Top-level PHPGuard menu
        add_menu_page(
            __( 'PHPGuard – Lite', 'phpguard-lite' ),
            __( 'PHPGuard', 'phpguard-lite' ),
            'manage_options',
            'phpguard-lite',
            array( $this, 'render_main_page' ),
            'dashicons-shield-alt',
            59
        );
    }

    public function enqueue_assets( $hook ) {
        if ( strpos( $hook, 'phpguard-lite' ) === false ) {
            return;
        }

        wp_enqueue_style(
            'phpguard-lite-admin',
            plugin_dir_url( __FILE__ ) . 'assets/phpguard-admin.css',
            array(),
            self::VERSION
        );

        wp_enqueue_script(
            'phpguard-lite-admin',
            plugin_dir_url( __FILE__ ) . 'assets/phpguard-admin.js',
            array( 'jquery' ),
            self::VERSION,
            true
        );

        wp_localize_script(
            'phpguard-lite-admin',
            'PHPGuardFree',
            array(
                'ajaxUrl' => admin_url( 'admin-ajax.php' ),
                'nonce'   => wp_create_nonce( 'phpguard_run_scan' ),
            )
        );
    }

    public function render_main_page() {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        $zip_install_result = null;
        $zip_scan_result    = null;

        $auto_install_disabled = (bool) get_option( 'phpguard_auto_install_disabled', false );
        if ( defined( 'PHPGUARD_DISABLE_INSTALL' ) && PHPGUARD_DISABLE_INSTALL ) {
            $auto_install_disabled = true;
        }
        // Handle "Install Now" for a previously scanned ZIP.
        if ( isset( $_POST['phpguard_install_zip_submit'] ) ) {
            if ( ! isset( $_POST['phpguard_install_zip_nonce'] ) ) {
                $zip_install_result = array(
                    'error' => __( 'Security check failed for ZIP install.', 'phpguard-lite' ),
                );
            } else {
                $nonce = sanitize_text_field( wp_unslash( $_POST['phpguard_install_zip_nonce'] ) );
                if ( ! wp_verify_nonce( $nonce, 'phpguard_install_zip' ) ) {
                    $zip_install_result = array(
                        'error' => __( 'Security check failed for ZIP install.', 'phpguard-lite' ),
                    );
                } elseif ( ! current_user_can( 'install_plugins' ) ) {
                    $zip_install_result = array(
                        'error' => __( 'You do not have permission to install plugins.', 'phpguard-lite' ),
                    );
                } else {
                    $zip_path_raw = isset( $_POST['phpguard_zip_path'] ) ? sanitize_text_field( wp_unslash( $_POST['phpguard_zip_path'] ) ) : '';

                    if ( '' === $zip_path_raw ) {
                        $zip_install_result = array(
                            'error' => __( 'No ZIP path was provided for install.', 'phpguard-lite' ),
                        );
                    } else {
                        $zip_path = realpath( $zip_path_raw );
                        $uploads  = wp_upload_dir();
                        $base_dir = realpath( $uploads['basedir'] );

                        if ( ! $zip_path || ! $base_dir || strpos( $zip_path, $base_dir ) !== 0 || substr( $zip_path, -4 ) !== '.zip' ) {
                            $zip_install_result = array(
                                'error' => __( 'The ZIP file location was invalid.', 'phpguard-lite' ),
                            );
                        } else {
                            require_once ABSPATH . 'wp-admin/includes/file.php';
                            require_once ABSPATH . 'wp-admin/includes/plugin.php';
                            require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';

                            $skin     = new Automatic_Upgrader_Skin();
                            $upgrader = new Plugin_Upgrader( $skin );
                            $result   = $upgrader->install( $zip_path );

                            $skin_errors = method_exists( $skin, 'get_errors' ) ? $skin->get_errors() : null;

                            if ( is_wp_error( $result ) ) {
                                $zip_install_result = array(
                                    'error' => sprintf(
                                        /* translators: %s: error message */
                                        __( 'Install failed: %s', 'phpguard-lite' ),
                                        $result->get_error_message()
                                    ),
                                );
                            } elseif ( $skin_errors instanceof WP_Error && $skin_errors->has_errors() ) {
                                $messages = $skin_errors->get_error_messages();
                                $zip_install_result = array(
                                    'error' => sprintf(
                                        /* translators: %s: error message */
                                        __( 'Install failed: %s', 'phpguard-lite' ),
                                        implode( ' ', $messages )
                                    ),
                                );
                            } elseif ( ! $result ) {
                                // Try to give a more helpful hint when the upgrader returns false with no explicit error.
                                $filesystem_method = function_exists( 'get_filesystem_method' ) ? get_filesystem_method() : '';
                                $zip_install_result = array(
                                    'error' => __( 'Install failed. Please try installing this ZIP via the standard Plugins → Add New → Upload Plugin screen.', 'phpguard-lite' ),
                                );
                                wp_delete_file( $zip_path );
                            }
                        }
                    }
                }
            }
        }
        if ( isset( $zip_install_result['error'] ) ) {
            update_option( 'phpguard_auto_install_disabled', true );
            $auto_install_disabled = true;
        }

        // Handle new ZIP uploads to scan.
        if ( isset( $_POST['phpguard_upload_zip_submit'] ) ) {
            if ( ! isset( $_POST['phpguard_upload_zip_nonce'] ) ) {
                $zip_scan_result = array(
                    'error' => __( 'Security check failed for ZIP upload.', 'phpguard-lite' ),
                );
            } else {
                $nonce = sanitize_text_field( wp_unslash( $_POST['phpguard_upload_zip_nonce'] ) );
                if ( ! wp_verify_nonce( $nonce, 'phpguard_upload_zip' ) ) {
                    $zip_scan_result = array(
                        'error' => __( 'Security check failed for ZIP upload.', 'phpguard-lite' ),
                    );
                } else {
                    $zip_scan_result = $this->handle_zip_upload_scan();
                }
            }
        }

$plugins = get_plugins();

        // Free runs in Safe Parser Mode and does not rely on PHP CLI.
        // Pro may optionally enable CLI-based deep checks when available.
        $environment_ok  = false;
        $environment_msg = __( 'PHPGuard is running in Safe Parser Mode. Advanced CLI scanning is not enabled in PHPGuard Lite.', 'phpguard-lite' );
        ?>
        <div class="wrap phpguard-lite-wrap">
            <h1><img src="<?php echo esc_url( plugins_url( 'assets/phpguard-logo.webp', __FILE__ ) ); ?>" style="height: 110px;margin-right:10px;vertical-align:middle;"> <?php esc_html_e( 'PHPGuard – Lite', 'phpguard-lite' ); ?></h1>
<style>
/* PHPGuard header slogan */
.phpguard-lite-wrap{
    position: relative;
}
.phpguard-slogan{
    position: absolute;
    top: 16px;
    left: 450px;
    max-width: 420px;
    font-size: 15px;
    font-style: italic;
    font-family: 'Segoe Script','Brush Script MT','Comic Sans MS', cursive;
    color: #5a6b7a;
    transform: rotate(-7deg);
}

/* On smaller screens, fall back to normal flow so layout doesn't break */
@media (max-width: 900px){
    .phpguard-slogan{
        position: static;
        transform: none;
        margin-top: 4px;
        margin-bottom: 18px;
    }
}
</style>

            <p class="phpguard-slogan"><?php esc_html_e( 'Scan plugins for PHP syntax errors before you activate them, to reduce the risk of crashes and white screens.', 'phpguard-lite' ); ?></p>

            
            <hr />

            <h2 class="nav-tab-wrapper phpguard-tabs-nav">
                <a href="#phpguard-tab-plugin" class="nav-tab nav-tab-active" data-phpguard-tab="plugin">
                    <?php esc_html_e( 'Quick Plugin Scan', 'phpguard-lite' ); ?>
                </a>
                <a href="#phpguard-tab-snippet" class="nav-tab" data-phpguard-tab="snippet">
                    <?php esc_html_e( 'Check Raw PHP Code Snippet', 'phpguard-lite' ); ?>
                </a>
                <a href="#phpguard-tab-zip" class="nav-tab" data-phpguard-tab="zip">
                    <?php esc_html_e( 'Scan Plugin ZIP Before Install', 'phpguard-lite' ); ?>
                </a>
                <a href="#phpguard-tab-env" class="nav-tab" data-phpguard-tab="env">
                    <?php esc_html_e( 'Environment Check', 'phpguard-lite' ); ?>
                </a>
                <a href="#phpguard-tab-docs" class="nav-tab" data-phpguard-tab="docs">
                    <?php esc_html_e( 'Documentation', 'phpguard-lite' ); ?>
                </a>
            </h2>

            <div class="phpguard-tabs-container">
                <div id="phpguard-tab-plugin" class="phpguard-tab-panel phpguard-tab-active">
                    <p><?php esc_html_e( 'Select an installed plugin and let PHPGuard run a syntax check on all of its PHP files using safe parser (if available).', 'phpguard-lite' ); ?></p>

                    <form id="phpguard-lite-form">
                        <label for="phpguard-plugin-select"><?php esc_html_e( 'Plugin to scan:', 'phpguard-lite' ); ?></label>
                        <select id="phpguard-plugin-select" name="plugin">
                            <?php foreach ( $plugins as $file => $data ) : ?>
                                <option value="<?php echo esc_attr( $file ); ?>">
                                    <?php echo esc_html( $data['Name'] ); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                        <button type="button" class="button button-primary" id="phpguard-run-scan">
                            <?php esc_html_e( 'Run Scan', 'phpguard-lite' ); ?>
                        </button>
                    </form>

                    <div id="phpguard-scan-result" style="margin-top: 1em;"></div>
                </div>

                <div id="phpguard-tab-snippet" class="phpguard-tab-panel" style="display:none;">
                    <p><?php esc_html_e( 'Paste PHP code below to check it for syntax errors before using it in your site.', 'phpguard-lite' ); ?></p>

                    <form id="phpguard-snippet-form" method="post" action="">
                        <?php wp_nonce_field( 'phpguard_run_scan', 'phpguard_snippet_nonce' ); ?>
                        <textarea id="phpguard-snippet" name="phpguard_snippet" rows="8" style="width:100%; max-width:900px;"></textarea>
                        <p style="margin-top: 0.5em;">
                            <button type="button" class="button button-secondary" id="phpguard-run-snippet-scan">
                                <?php esc_html_e( 'Check Pasted Code', 'phpguard-lite' ); ?>
                            </button>
                        </p>
                    </form>

                    <div id="phpguard-snippet-result" style="margin-top: 1em;"></div>
                </div>

                <div id="phpguard-tab-zip" class="phpguard-tab-panel" style="display:none;">
                    <p><?php esc_html_e( 'Upload a plugin ZIP file to run a pre-install syntax scan. The ZIP will be scanned in a temporary folder and then removed.', 'phpguard-lite' ); ?></p>

            <?php if ( ! empty( $zip_scan_result ) && is_array( $zip_scan_result ) ) : ?>
    <div id="phpguard-zip-result" style="margin-top: 1em;">
        <?php if ( isset( $zip_scan_result['error'] ) ) : ?>
            <div class="notice notice-error"><p><?php echo esc_html( $zip_scan_result['error'] ); ?></p></div>
        <?php else : ?>
            <p><strong><?php echo esc_html( isset( $zip_scan_result['message'] ) ? $zip_scan_result['message'] : '' ); ?></strong></p>

            <?php if ( isset( $zip_scan_result['filesChecked'] ) ) : ?>
                <p><?php esc_html_e( 'Files checked:', 'phpguard-lite' ); ?> <strong><?php echo esc_html( $zip_scan_result['filesChecked'] ); ?></strong></p>
            <?php endif; ?>

            <?php if ( ! empty( $zip_scan_result['errors'] ) && is_array( $zip_scan_result['errors'] ) ) : ?>
                <ol>
                    <?php foreach ( $zip_scan_result['errors'] as $error ) : ?>
                        <li>
                            <strong><code><?php echo esc_html( isset( $error['file'] ) ? $error['file'] : '' ); ?></code></strong><br />
                            <?php echo esc_html( isset( $error['message'] ) ? $error['message'] : '' ); ?>
                        </li>
                    <?php endforeach; ?>
                </ol>
            <?php endif; ?>

            <?php if ( ! empty( $zip_scan_result['indicators'] ) && is_array( $zip_scan_result['indicators'] ) ) : ?>
                <h4 style="margin-top:18px;"><?php esc_html_e( 'Suspicious indicators', 'phpguard-lite' ); ?></h4>
                <p style="margin-top:6px;"><?php esc_html_e( 'These are informational only. Nothing is executed.', 'phpguard-lite' ); ?></p>
                <div class="phpguard-indicators" style="overflow:auto;">
                    <table class="widefat striped" style="margin-top:8px;">
                        <thead>
                            <tr>
                                <th><?php esc_html_e( 'Severity', 'phpguard-lite' ); ?></th>
                                <th><?php esc_html_e( 'Indicator', 'phpguard-lite' ); ?></th>
                                <th><?php esc_html_e( 'File', 'phpguard-lite' ); ?></th>
                                <th><?php esc_html_e( 'Line', 'phpguard-lite' ); ?></th>
                                <th><?php esc_html_e( 'What / Next', 'phpguard-lite' ); ?></th>
                                <th><?php esc_html_e( 'Excerpt', 'phpguard-lite' ); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ( $zip_scan_result['indicators'] as $ind ) : ?>
                                <tr>
                                    <td><strong><?php echo esc_html( isset( $ind['severity'] ) ? $ind['severity'] : '' ); ?></strong></td>
                                    <td><?php echo esc_html( isset( $ind['indicator'] ) ? $ind['indicator'] : '' ); ?></td>
                                    <td><code><?php echo esc_html( isset( $ind['file'] ) ? $ind['file'] : '' ); ?></code></td>
                                    <td><?php echo esc_html( isset( $ind['line'] ) ? $ind['line'] : '' ); ?></td>
                                    <td>
                                        <?php
                                        $what = isset( $ind['what'] ) ? (string) $ind['what'] : '';
                                        $next = isset( $ind['next'] ) ? (string) $ind['next'] : '';
                                        echo esc_html( $what );
                                        if ( $next ) {
                                            echo '<br /><em>' . esc_html__( 'Next:', 'phpguard-lite' ) . '</em> ' . esc_html( $next );
                                        }
                                        ?>
                                    </td>
                                    <td><code><?php echo esc_html( isset( $ind['excerpt'] ) ? $ind['excerpt'] : '' ); ?></code></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>
        <?php endif; ?>
    </div>
<?php endif; ?>

            <?php if ( ! empty( $zip_install_result ) && is_array( $zip_install_result ) ) : ?>
                <div class="notice notice-<?php echo isset( $zip_install_result['error'] ) ? 'error' : 'success'; ?>">
                    <p>
                        <?php
                        if ( isset( $zip_install_result['error'] ) ) {
                            echo esc_html( $zip_install_result['error'] );
                        } else {
                            echo esc_html( $zip_install_result['message'] );
                        }
                        ?>
                    </p>
                </div>
            <?php endif; ?>

            <?php
            $phpguard_can_install_zip = (
                ! empty( $zip_scan_result )
                && is_array( $zip_scan_result )
                && empty( $zip_scan_result['error'] )
                && empty( $zip_scan_result['errors'] )
                && ! empty( $zip_scan_result['zip_path'] )
            );
            ?>

            <?php
            $phpguard_env_allows_install = false; // Automatic installs disabled – always direct to manual Upload Plugin page.

            if ( ! $phpguard_env_allows_install && $phpguard_can_install_zip ) :
            ?>
                <div class="phpguard-host-warning" style="display:none;">
                    <p><?php esc_html_e( 'Your hosting environment prevents automated plugin installs. PHPGuard can safely scan ZIP files, but you will need to install the plugin manually via Plugins → Add New → Upload Plugin.', 'phpguard-lite' ); ?></p>
                </div>
            <?php endif; ?>

            <?php if ( $phpguard_can_install_zip && $phpguard_env_allows_install ) : ?>
                <form method="post" style="margin-bottom: 1em;" id="phpguard-install-zip-form">
                    <?php wp_nonce_field( 'phpguard_install_zip', 'phpguard_install_zip_nonce' ); ?>
                    <input type="hidden" name="phpguard_zip_path" value="<?php echo esc_attr( $zip_scan_result['zip_path'] ); ?>" />
                    <?php submit_button( __( 'Install This Plugin Now', 'phpguard-lite' ), 'primary', 'phpguard_install_zip_submit', false ); ?>
                </form>
            <?php endif; ?>
            <div id="phpguard-install-meta"
                 data-can-install="<?php echo $phpguard_can_install_zip ? '1' : '0'; ?>"
                 data-env-allows="<?php echo $phpguard_env_allows_install ? '1' : '0'; ?>"
                 data-upload-url="<?php echo esc_url( admin_url( 'plugin-install.php?tab=upload' ) ); ?>">
            </div>

            <form method="post" enctype="multipart/form-data">
                <?php wp_nonce_field( 'phpguard_upload_zip', 'phpguard_upload_zip_nonce' ); ?>
                <input type="file" name="phpguard_plugin_zip" accept=".zip" />
                <?php submit_button( __( 'Upload and Scan ZIP', 'phpguard-lite' ), 'secondary', 'phpguard_upload_zip_submit', false ); ?>
            </form>
</div></div>
            </div>
                <div id="phpguard-tab-env" class="phpguard-tab-panel" style="display:none;">
                    <h2><?php esc_html_e( 'Environment &amp; Host Check', 'phpguard-lite' ); ?></h2>
                    <p><?php esc_html_e( 'This tab shows which scan engine PHPGuard is using on this server.', 'phpguard-lite' ); ?></p>
                    <p><strong><?php esc_html_e( 'Current status:', 'phpguard-lite' ); ?></strong> <?php echo esc_html( $environment_msg ); ?></p>
                    <p><?php esc_html_e( 'Safe Parser Mode performs syntax checks without executing code. PHPGuard Pro may optionally enable advanced CLI-based scanning on hosts that support it.', 'phpguard-lite' ); ?></p>
                </div>
                <div id="phpguard-tab-docs" class="phpguard-tab-panel" style="display:none;">
                    <h2><?php esc_html_e( 'How PHPGuard Works', 'phpguard-lite' ); ?></h2>
                    <p><?php esc_html_e( 'Use these tabs to run different kinds of checks before you install or activate plugins on a live site.', 'phpguard-lite' ); ?></p>

                    <h3><?php esc_html_e( 'Quick Plugin Scan', 'phpguard-lite' ); ?></h3>
                    <p><?php esc_html_e( 'Select any installed plugin and run a fast syntax scan on its PHP files. PHPGuard uses safe parser (if available) to detect fatal errors that would cause a white screen or crash when the plugin runs.', 'phpguard-lite' ); ?></p>

                    <h3><?php esc_html_e( 'Check Raw PHP Code Snippet', 'phpguard-lite' ); ?></h3>
                    <p><?php esc_html_e( 'Paste a single PHP snippet or small block of code and let PHPGuard check it for syntax errors before you drop it into functions.php, a custom plugin, or a code snippets plugin.', 'phpguard-lite' ); ?></p>

                    <h3><?php esc_html_e( 'Scan Plugin ZIP Before Install', 'phpguard-lite' ); ?></h3>
                    <p><?php esc_html_e( 'Upload a plugin ZIP file before you install it. PHPGuard unpacks the archive in a temporary folder, runs syntax checks, and then cleans up. This helps catch broken downloads or bad third‑party code before it ever touches your Plugins list.', 'phpguard-lite' ); ?></p>

                    <h3><?php esc_html_e( 'Environment Check', 'phpguard-lite' ); ?></h3>
                    <p><?php esc_html_e( 'This tab shows which scan engine PHPGuard is using. In PHPGuard Lite, scans run in Safe Parser Mode (no code is executed). PHPGuard Pro may optionally enable advanced CLI-based scanning when a host supports it.', 'phpguard-lite' ); ?></p>
                    
                    <h3><?php esc_html_e( 'PHPGuard Pro — Coming Soon', 'phpguard-lite' ); ?></h3>
                    <p><?php esc_html_e( 'PHPGuard Pro will build on the free safety checks with powerful automation and protection features designed for serious WordPress professionals, agencies, and mission-critical sites.', 'phpguard-lite' ); ?></p>
                    <ul class="ul-disc">
                        <li><?php esc_html_e( 'Real-time crash prevention to stop bad code before it takes down a live site.', 'phpguard-lite' ); ?></li>
                        <li><?php esc_html_e( 'Automatic SMART rollback safety nets when a plugin update or custom code breaks a site.', 'phpguard-lite' ); ?></li>
                        <li><?php esc_html_e( 'Backup and SMART rollback of database (per plugin) or GLOBAL.', 'phpguard-lite' ); ?></li>
                        <li><?php esc_html_e( 'Deeper and smarter analysis than basic safe parser syntax checks.', 'phpguard-lite' ); ?></li>
                        <li><?php esc_html_e( 'Professional-grade workflows built for agencies and power users.', 'phpguard-lite' ); ?></li>
                    </ul>

                    <h3><?php esc_html_e( 'Support', 'phpguard-lite' ); ?></h3>
                    <p><?php esc_html_e( 'Prefer a one‑time way to say thank you? You can support PHPGuard development.', 'phpguard-lite' ); ?></p>
                    <p>
                        <a class="button button-primary phpguard-donate-button" href="https://www.paypal.com/donate/?business=info%40phpguard.dev&item_name=Support+PHPGuard&currency_code=USD" target="_blank" rel="noopener">
                            <?php esc_html_e( 'Buy me a coffee', 'phpguard-lite' ); ?>
                        </a>
                    </p>

</div>

<div class="phpguard-pro-panel">
    <h2><?php esc_html_e( 'PHPGuard Pro', 'phpguard-lite' ); ?></h2>

    <p style="margin:12px 0;">
        <strong><?php esc_html_e( 'PHPGuard Pro is coming.', 'phpguard-lite' ); ?></strong>
        <?php esc_html_e( 'Learn what Pro will include and follow updates on the project site.', 'phpguard-lite' ); ?>
        <a href="<?php echo esc_url( 'https://phpguard.dev/prevent-wordpress-plugin-errors/' ); ?>" target="_blank" rel="noopener noreferrer">
            <?php esc_html_e( 'Learn more', 'phpguard-lite' ); ?>
        </a>
    </p>

    <?php
    printf(
        /* translators: %s: version number */
        esc_html__( 'PHPGuard Pre-Install Safety Checker version %s', 'phpguard-lite' ),
        esc_html( self::VERSION )
    );
    ?>
</div>
     <?php
    }

    /**
     * Render the shared version history view.
     */
    public function render_version_history_page() {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        $history  = get_option( self::OPTION_HISTORY );
        if ( ! is_array( $history ) ) {
            $history = array();
        }

        // Newest first.
        usort(
            $history,
            function ( $a, $b ) {
                $ta = isset( $a['timestamp'] ) ? (int) $a['timestamp'] : 0;
                $tb = isset( $b['timestamp'] ) ? (int) $b['timestamp'] : 0;
                return $tb - $ta;
            }
        );

        ?>
        <div class="wrap phpguard-lite-wrap">
            <h1><img src="<?php echo esc_url( plugins_url( 'assets/phpguard-logo.webp', __FILE__ ) ); ?>" style="height: 110px;margin-right:10px;vertical-align:middle;"> <?php esc_html_e( 'PHPGuard Version History', 'phpguard-lite' ); ?></h1>
            <p><?php esc_html_e( 'This table shows recorded updates for the PHPGuard Pre-Install Safety Checker (free plugin, and related admin tools).', 'phpguard-lite' ); ?></p>

            <?php if ( empty( $history ) ) : ?>
                <p><?php esc_html_e( 'No version history has been recorded yet.', 'phpguard-lite' ); ?></p>
            <?php else : ?>
                <table class="widefat fixed striped">
                    <thead>
                        <tr>
                            <th><?php esc_html_e( 'Date', 'phpguard-lite' ); ?></th>
                            <th><?php esc_html_e( 'Component', 'phpguard-lite' ); ?></th>
                            <th><?php esc_html_e( 'Version', 'phpguard-lite' ); ?></th>
                            <th><?php esc_html_e( 'Notes', 'phpguard-lite' ); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ( $history as $entry ) : ?>
                            <tr>
                                <td>
                                    <?php
                                    $ts = isset( $entry['timestamp'] ) ? (int) $entry['timestamp'] : 0;
                                    if ( $ts ) {
                                        echo esc_html( date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $ts ) );
                                    } else {
                                        esc_html_e( '(unknown)', 'phpguard-lite' );
                                    }
                                    ?>
                                </td>
                                <td><?php echo esc_html( isset( $entry['component'] ) ? $entry['component'] : '' ); ?></td>
                                <td><?php echo esc_html( isset( $entry['version'] ) ? $entry['version'] : '' ); ?></td>
                                <td><?php echo esc_html( isset( $entry['notes'] ) ? $entry['notes'] : '' ); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>
        <?php
    }

    /**
     * Ajax: run scan for selected plugin.
     */
    public function ajax_run_scan() {
        if ( ! check_ajax_referer( 'phpguard_run_scan', 'nonce', false ) ) {
            wp_send_json_error( array( 'message' => __( 'Security check failed. Please refresh and try again.', 'phpguard-lite' ) ) );
        }
if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array( 'message' => __( 'Permission denied.', 'phpguard-lite' ) ) );
        }

        $plugin = isset( $_POST['plugin'] ) ? sanitize_text_field( wp_unslash( $_POST['plugin'] ) ) : '';
        if ( empty( $plugin ) ) {
            wp_send_json_error( array( 'message' => __( 'No plugin specified.', 'phpguard-lite' ) ) );
        }

        $plugins = get_plugins();
        if ( ! isset( $plugins[ $plugin ] ) ) {
            wp_send_json_error( array( 'message' => __( 'Unknown plugin.', 'phpguard-lite' ) ) );
        }

        $plugin_dir = WP_PLUGIN_DIR . '/' . dirname( $plugin );
        if ( ! is_dir( $plugin_dir ) ) {
            wp_send_json_error( array( 'message' => __( 'Plugin folder not found.', 'phpguard-lite' ) ) );
        }

        $results = $this->scan_directory_for_php_errors( $plugin_dir );

        wp_send_json_success( $results );
    }


    /**
     * Ajax: run syntax scan for pasted PHP code.
     */
    public 
    function ajax_run_snippet_scan() {
        if ( ! check_ajax_referer( 'phpguard_run_scan', 'nonce', false ) ) {
            wp_send_json_error( array( 'message' => __( 'Security check failed. Please refresh and try again.', 'phpguard-lite' ) ) );
        }
if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error(
                array(
                    'message' => __( 'Permission denied.', 'phpguard-lite' ),
                )
            );
        }

$snippet = '';

if ( isset( $_POST['snippet'] ) ) {
    // Plain text mode (older JS or fallback)
    $snippet = isset( $_POST['snippet'] ) ? sanitize_textarea_field( wp_unslash( $_POST['snippet'] ) ) : '';
} elseif ( isset( $_POST['snippet_b64'] ) ) {
    // Base64 mode (current JS)
    $raw = sanitize_textarea_field( wp_unslash( $_POST['snippet_b64'] ) );
    $decoded = base64_decode( $raw, true );
    if ( false === $decoded ) {
        wp_send_json_error(
            array(
                'message' => __( 'Invalid snippet encoding.', 'phpguard-lite' ),
            )
        );
    }
    $snippet = $decoded;
}

if ( '' === trim( $snippet ) ) {
    wp_send_json_error(
        array(
            'message' => __( 'No code was provided.', 'phpguard-lite' ),
        )
    );
}

        // Ensure the code is wrapped in PHP tags so safe parser can lint it reliably.
        if ( false === strpos( $snippet, '<?' ) ) {
            $snippet = "<?php\n" . $snippet;
        }

        $tmp_file = wp_tempnam( 'phpguard_snippet.php' );
        if ( ! $tmp_file ) {
            wp_send_json_error(
                array(
                    'message' => __( 'Could not create a temporary file for the snippet scan.', 'phpguard-lite' ),
                )
            );
        }

        file_put_contents( $tmp_file, $snippet );

        $results = array(
            'message'      => '',
            'filesChecked' => 1,
            'errors'       => array(),
            // Suspicious patterns (informational; nothing is executed).
            'indicators'   => array(),
        );

        $output_text   = '';
        $exit_code     = 0;

        // Non-executing syntax check using nikic/php-parser.
        $result = $this->basic_php_syntax_check( $tmp_file );
        if ( true !== $result ) {
            $output_text = (string) $result;
            $exit_code   = 1;
        }

        if ( $output_text ) {
            $output_text = $this->normalize_php_lint_output( $output_text, $tmp_file );
            $output_text = $this->clean_php_error_message( $output_text );
        }

        wp_delete_file( $tmp_file );

        $has_error = false;

        if ( 0 !== $exit_code ) {
            $has_error = true;
        } elseif ( $output_text && preg_match( '/(Errors parsing|Parse error|syntax error|Fatal error|PHP Parse error)/i', $output_text ) ) {
            $has_error = true;
        }

        if ( $has_error ) {
            $results['message'] = __( 'Detected syntax issues in the pasted code. Review details below.', 'phpguard-lite' );
            $results['errors'][] = array(
                'file'    => __( 'Pasted code snippet', 'phpguard-lite' ),
                'message' => $output_text ? $output_text : __( 'Unknown parse error reported by PHP.', 'phpguard-lite' ),
            );
        } else {
            $results['message'] = __( 'No syntax errors detected in the pasted code.', 'phpguard-lite' );
        }

        // Add informational suspicious-pattern indicators (even if syntax is clean).
        $results['indicators'] = $this->detect_indicators_in_code( $snippet );

        wp_send_json_success( $results );
    }

    /**
     * Detect suspicious patterns in a code string without executing anything.
     * This is intentionally heuristic and informational only.
     */
    protected function detect_indicators_in_code( $code ) {
        $out = array();
        if ( ! is_string( $code ) || '' === trim( $code ) ) {
            return $out;
        }

        // Functions that are commonly abused in malicious PHP code.
        // Used only for detection and for labeling scan results.
        $fn_eval        = 'eval';
        $fn_assert      = 'assert';
        $fn_exec        = 'exec';
        $fn_system      = 'system';
        $fn_shell_exec  = 'shell_exec';
        $fn_passthru    = 'passthru';
        $fn_proc_open   = 'proc_open';
        $fn_popen       = 'popen';
        $fn_create_func = 'create_function';

        $danger_words = array(
            $fn_eval,
            $fn_assert,
            $fn_system,
            $fn_exec,
            $fn_shell_exec,
            $fn_passthru,
            $fn_proc_open,
            $fn_popen,
            $fn_create_func,
        );
        $obf_word = function( $w ) { return (string) $w; };
        $obf_text = function( $t ) { return (string) $t; };



        // Token-based detection.
        $tokens = token_get_all( $code );
        if ( is_array( $tokens ) ) {
            $danger_map = array(
                ( defined( 'T_EVAL' ) ? T_EVAL : -1 ) => array( 'severity' => 'HIGH', 'indicator' => $fn_eval,   'what' => 'eval() language construct', 'next' => 'Never run untrusted code; prefer parsing only.' ),
            );
            $count_tokens = count( $tokens );
            for ( $i = 0; $i < $count_tokens; $i++ ) {
                $t = $tokens[ $i ];
                if ( is_array( $t ) ) {
                    $tid = $t[0];
                    $tval = $t[1];
                    $tline = isset( $t[2] ) ? (int) $t[2] : 0;

                    if ( isset( $danger_map[ $tid ] ) ) {
                        $info = $danger_map[ $tid ];
                        $out[] = array(
                            'severity'  => $info['severity'],
                            'indicator' => $obf_word($info['indicator']),
                            'line'      => max( 1, $tline ),
                            'excerpt'   => trim( $tval ),
                            'what'      => $obf_text($info['what']),
                            'next'      => $info['next'],
                        );
                        continue;
                    }

                    // Function-call style: system(), exec(), shell_exec(), passthru(), proc_open(), popen(), create_function(), assert()
                    if ( T_STRING === $tid ) {
                        $name = strtolower( $tval );
                        $watch = array(
                            $fn_assert,
                            $fn_exec,
                            $fn_shell_exec,
                            $fn_system,
                            $fn_passthru,
                            $fn_proc_open,
                            $fn_popen,
                            $fn_create_func,
                        );
                        if ( in_array( $name, $watch, true ) ) {
                            // Look ahead for "(" ignoring whitespace/comments.
                            $j = $i + 1;
                            while ( $j < $count_tokens ) {
                                $n = $tokens[ $j ];
                                if ( is_array( $n ) ) {
                                    if ( in_array( $n[0], array( T_WHITESPACE, T_COMMENT, T_DOC_COMMENT ), true ) ) {
                                        $j++;
                                        continue;
                                    }
                                    break;
                                } else {
                                    break;
                                }
                            }
                            if ( $j < $count_tokens && '(' === $tokens[ $j ] ) {
                                // Avoid duplicates if regex also catches it later.
                                $out[] = array(
                                    'severity'  => ( $name === $fn_create_func ? 'MEDIUM' : 'HIGH' ),
                                    'indicator' => $name,
                                    'line'      => max( 1, $tline ),
                                    'excerpt'   => trim( $name . '(' ),
                                    'what'      => $name . '() call',
                                    'next'      => 'Confirm no user input reaches this call; review for webshell patterns.',
                                );
                            }
                        }
                    }
                }
            }
        }
        $rules = array(
            array(
                'severity'  => 'HIGH',
                'indicator' => $fn_eval,
                'pattern'   => '/\b' . preg_quote( $fn_eval, '/' ) . '\s*\(/i',
                'what'      => $fn_eval . '() call',
                'next'      => 'Do not execute user-controlled strings; remove or replace with safer logic.',
            ),
            array(
                'severity'  => 'HIGH',
                'indicator' => $fn_assert,
                'pattern'   => '/\b' . preg_quote( $fn_assert, '/' ) . '\s*\(/i',
                'what'      => $fn_assert . '() call',
                'next'      => 'In some contexts this can execute code; avoid with untrusted input.',
            ),
            array(
                'severity'  => 'HIGH',
                'indicator' => $fn_system,
                'pattern'   => '/\b' . preg_quote( $fn_system, '/' ) . '\s*\(/i',
                'what'      => $fn_system . '() call',
                'next'      => 'Runs OS commands. Confirm no user input reaches it; review for webshell patterns.',
            ),
            array(
                'severity'  => 'HIGH',
                'indicator' => $fn_exec,
                'pattern'   => '/\b' . preg_quote( $fn_exec, '/' ) . '\s*\(/i',
                'what'      => $fn_exec . '() call',
                'next'      => 'Runs OS commands. Confirm no user input reaches it; review for webshell patterns.',
            ),
            array(
                'severity'  => 'HIGH',
                'indicator' => $fn_shell_exec,
                'pattern'   => '/\b' . preg_quote( $fn_shell_exec, '/' ) . '\s*\(/i',
                'what'      => $fn_shell_exec . '() call',
                'next'      => 'Runs OS commands. Confirm no user input reaches it; review for webshell patterns.',
            ),
            array(
                'severity'  => 'HIGH',
                'indicator' => $fn_passthru,
                'pattern'   => '/\b' . preg_quote( $fn_passthru, '/' ) . '\s*\(/i',
                'what'      => $fn_passthru . '() call',
                'next'      => 'Runs OS commands. Confirm no user input reaches it; review for webshell patterns.',
            ),
            array(
                'severity'  => 'HIGH',
                'indicator' => $fn_proc_open,
                'pattern'   => '/\b' . preg_quote( $fn_proc_open, '/' ) . '\s*\(/i',
                'what'      => $fn_proc_open . '() call',
                'next'      => 'Spawns processes. Confirm no user input reaches it; review for webshell patterns.',
            ),
            array(
                'severity'  => 'HIGH',
                'indicator' => $fn_popen,
                'pattern'   => '/\b' . preg_quote( $fn_popen, '/' ) . '\s*\(/i',
                'what'      => $fn_popen . '() call',
                'next'      => 'Spawns processes. Confirm no user input reaches it; review for webshell patterns.',
            ),
            array(
                'severity'  => 'MEDIUM',
                'indicator' => $fn_create_func,
                'pattern'   => '/\b' . preg_quote( $fn_create_func, '/' ) . '\s*\(/i',
                'what'      => $fn_create_func . '() call',
                'next'      => 'Deprecated and risky. Prefer closures.',
            ),
            array(
                'severity'  => 'MEDIUM',
                'indicator' => 'preg_replace_e',
                'pattern'   => '/preg_replace\s*\(\s*[^,]*\/e[\"\']?\s*,/i',
                'what'      => 'preg_replace() with /e',
                'next'      => 'Historically dangerous. Remove /e; use preg_replace_callback.',
            ),
        );

        $lines = preg_split( "/\r\n|\r|\n/", $code );
        foreach ( $rules as $r ) {
            if ( ! isset( $r['pattern'] ) ) {
                continue;
            }
            if ( preg_match_all( $r['pattern'], $code, $m, PREG_OFFSET_CAPTURE ) ) {
                foreach ( $m[0] as $hit ) {
                    $pos  = (int) $hit[1];
                    $line = 1 + substr_count( substr( $code, 0, max( 0, $pos ) ), "\n" );
                    $excerpt = '';
                    if ( isset( $lines[ $line - 1 ] ) ) {
                        $excerpt = trim( $lines[ $line - 1 ] );
                    }
                    $out[] = array(
                        'severity'  => $r['severity'],
                        'indicator' => $r['indicator'],
                        'line'      => $line,
                        'excerpt'   => $excerpt,
                        'what'      => $r['what'],
                        'next'      => $r['next'],
                    );
                }
            }
        }
        $merged = array();

        foreach ( $out as $row ) {
            $key = strtolower( $row['indicator'] ) . '|' . (int) $row['line'];

            if ( ! isset( $merged[ $key ] ) ) {
                $merged[ $key ] = $row;
                continue;
            }

            // Merge "what" text
            if ( false === stripos( $merged[ $key ]['what'], $row['what'] ) ) {
                $merged[ $key ]['what'] .= ' / ' . $row['what'];
            }

            // Merge "next" guidance
            if ( false === stripos( $merged[ $key ]['next'], $row['next'] ) ) {
                $merged[ $key ]['next'] .= ' ' . $row['next'];
            }
        }

        return array_values( $merged );
    }

    /**
     * Detect indicators in a file and annotate each hit with a relative file path.
     *
     * @param string $file Absolute path.
     * @param string $base_dir Base directory for relative paths.
     * @return array<int,array{severity:string,indicator:string,line:int,excerpt:string,what:string,next:string,file:string}>
     */
    protected function detect_indicators_in_file( $file, $base_dir ) {
        $hits = array();
        if ( ! is_string( $file ) || '' === $file || ! file_exists( $file ) ) {
            return $hits;
        }

        $code = file_get_contents( $file );
        if ( false === $code ) {
            return $hits;
        }

        $rel = $file;
        if ( is_string( $base_dir ) && '' !== $base_dir ) {
            $base_dir = rtrim( str_replace( '\\', '/', $base_dir ), '/' ) . '/';
            $norm_file = str_replace( '\\', '/', $file );
            if ( 0 === strpos( $norm_file, $base_dir ) ) {
                $rel = substr( $norm_file, strlen( $base_dir ) );
            }
        }

        $found = $this->detect_indicators_in_code( $code );
        if ( empty( $found ) ) {
            return $hits;
        }

        foreach ( $found as $row ) {
            $row['file'] = $rel;
            $hits[] = $row;
        }
        return $hits;
    }
    /**
     * Handle ZIP uploads from the admin screen, extract them and scan for PHP syntax errors.
     *
     * @return array
     */
    protected function handle_zip_upload_scan() {
        
        // Security: verify nonce for ZIP upload action (PHPCS requires this where $_FILES is processed).
        if ( ! isset( $_POST['phpguard_upload_zip_nonce'] ) ) {
            return array(
                'error' => __( 'Security check failed for ZIP upload.', 'phpguard-lite' ),
            );
        }

        $nonce = sanitize_text_field( wp_unslash( $_POST['phpguard_upload_zip_nonce'] ) );
        if ( ! wp_verify_nonce( $nonce, 'phpguard_upload_zip' ) ) {
            return array(
                'error' => __( 'Security check failed for ZIP upload.', 'phpguard-lite' ),
            );
        }

        // Basic upload presence check.
        if ( ! isset( $_FILES['phpguard_plugin_zip'] ) || empty( $_FILES['phpguard_plugin_zip']['tmp_name'] ) ) {
            return array(
                'error' => __( 'No ZIP file was uploaded.', 'phpguard-lite' ),
            );
        }

        // Make sure the core upload functions are available.
        if ( ! function_exists( 'wp_handle_upload' ) ) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }

        $overrides = array(
            'test_form' => false,
            'mimes'     => array(
                'zip' => 'application/zip',
            ),
        );

        $uploaded = wp_handle_upload( $_FILES['phpguard_plugin_zip'], $overrides );

        if ( isset( $uploaded['error'] ) ) {
            return array(
                'error' => sprintf(
                    /* translators: %s: upload error message */
                    __( 'Upload error: %s', 'phpguard-lite' ),
                    $uploaded['error']
                ),
            );
        }

        $zip_path = $uploaded['file'];

        // Create a temporary directory for extraction.
        $uploads    = wp_upload_dir();
        $temp_dir   = trailingslashit( $uploads['basedir'] ) . 'phpguard-temp-' . wp_generate_password( 8, false, false );
        $created_ok = wp_mkdir_p( $temp_dir );

        if ( ! $created_ok ) {
            wp_delete_file( $zip_path );
            return array(
                'error' => __( 'Could not create a temporary directory to inspect the ZIP.', 'phpguard-lite' ),
            );
        }

        $extracted_ok = false;

        if ( class_exists( 'ZipArchive' ) ) {
            $zip = new ZipArchive();
            if ( true === $zip->open( $zip_path ) ) {
                $extracted_ok = $zip->extractTo( $temp_dir );
                $zip->close();
            }
        }

        if ( ! $extracted_ok ) {
            // Cleanup and report error.
            $this->delete_directory_recursively( $temp_dir );
            wp_delete_file( $zip_path );

            return array(
                'error' => __( 'Could not extract the ZIP file for scanning.', 'phpguard-lite' ),
            );
        }

        // Run the actual scan on the extracted folder.
        $results = $this->scan_directory_for_php_errors( $temp_dir );

        
        // Normalize error file paths to be relative to the extracted ZIP root for cleaner reporting.
        if ( ! empty( $results['errors'] ) && is_array( $results['errors'] ) ) {
            foreach ( $results['errors'] as $i => $err ) {
                if ( isset( $err['file'] ) && is_string( $err['file'] ) ) {
                    $f = str_replace( '\\', '/', $err['file'] );
                    $base = rtrim( str_replace( '\\', '/', $temp_dir ), '/' ) . '/';
                    if ( 0 === strpos( $f, $base ) ) {
                        $results['errors'][ $i ]['file'] = substr( $f, strlen( $base ) );
                    }
                }
            }
        }
// Always expose the ZIP path so the UI can offer installation later.
        $results['zip_path'] = $zip_path;

        // Cleanup temporary directory. We keep the uploaded ZIP so it can be installed if desired.
        $this->delete_directory_recursively( $temp_dir );

        // Return a summary message.
        if ( empty( $results['message'] ) ) {
            if ( empty( $results['errors'] ) ) {
                $results['message'] = __( 'No syntax errors detected in the uploaded ZIP.', 'phpguard-lite' );
            } else {
                $results['message'] = sprintf(
                    /* translators: %d: number of files with errors */
                    __( 'Detected issues in %d file(s) in the uploaded ZIP.', 'phpguard-lite' ),
                    count( $results['errors'] )
                );
            }
        }

        return $results;
    }

/**
 * Scan all PHP files in a directory tree using nikic/php-parser (non-executing).
 */
protected function scan_directory_for_php_errors( $dir ) {
    $files = $this->list_php_files( $dir );

    $results = array(
        'filesChecked' => count( $files ),
        'errors'       => array(),
        // Informational only (no execution). Present for both snippet and plugin scans.
        'indicators'   => array(),
    );

    if ( empty( $files ) ) {
        $results['message'] = __( 'No PHP files found in this plugin.', 'phpguard-lite' );
        return $results;
    }

    foreach ( $files as $file ) {
        $result = $this->basic_php_syntax_check( $file ); // parser-based
        if ( $result !== true ) {
            $result = $this->clean_php_error_message( $result );
            $results['errors'][] = array(
                'file'    => $file,
                'message' => $result,
            );
        }

        // Collect informational indicators for this file (even if syntax OK).
        $inds = $this->detect_indicators_in_file( $file, $dir );
        if ( ! empty( $inds ) ) {
            $results['indicators'] = array_merge( $results['indicators'], $inds );
        }
    }

    if ( empty( $results['errors'] ) ) {
        $results['message'] = __( 'No syntax errors detected in the scanned plugin.', 'phpguard-lite' );
    } else {
        $results['message'] = sprintf(
            /* translators: %d: number of files with errors */
            __( 'Detected issues in %d file(s). Review details below.', 'phpguard-lite' ),
            count( $results['errors'] )
        );
    }

    return $results;
}

/**
     * Recursively delete a directory and all of its contents.
     *
     * @param string $dir Directory path.
     */
    protected function delete_directory_recursively( $dir ) {
        if ( ! is_dir( $dir ) ) {
            return;
        }

        $items = scandir( $dir );
        if ( ! is_array( $items ) ) {
            return;
        }

        foreach ( $items as $item ) {
            if ( $item === '.' || $item === '..' ) {
                continue;
            }

            $path = $dir . DIRECTORY_SEPARATOR . $item;
            if ( is_dir( $path ) ) {
                $this->delete_directory_recursively( $path );
            } else {
                wp_delete_file( $path );
            }
        }

        wp_delete_file( $dir );
    }

    /**
     * Recursively list all PHP files in a directory.
     */
    protected function list_php_files( $dir ) {
        $files = array();

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator(
                $dir,
                RecursiveDirectoryIterator::SKIP_DOTS
            )
        );

        foreach ( $iterator as $file ) {
            /** @var SplFileInfo $file */
            if ( $file->isFile() && strtolower( $file->getExtension() ) === 'php' ) {
                $files[] = $file->getPathname();
            }
        }

        return $files;
    }

    /**
     * Syntax check using nikic/php-parser.
     *
     * @param string $file Absolute path to a PHP file.
     * @return true|string True if OK, otherwise an error string.
     */
    protected function basic_php_syntax_check( $file ) {
        $code = file_get_contents( $file );
        if ( $code === false ) {
            return __( 'Unable to read file.', 'phpguard-lite' );
        }

        // Load bundled parser (no composer required).
        if ( ! class_exists( '\\PhpParser\\ParserFactory' ) ) {
            $autoload = __DIR__ . '/vendor/nikic/php-parser/autoload.php';
            if ( file_exists( $autoload ) ) {
                require_once $autoload;
            }
        }

        if ( ! class_exists( '\\PhpParser\\ParserFactory' ) ) {
            return __( 'Parser unavailable. Unable to check syntax safely.', 'phpguard-lite' );
        }

        try {
            $parser = ( new \PhpParser\ParserFactory() )->createForNewestSupportedVersion();
            $parser->parse( $code );
            return true;
        } catch ( \PhpParser\Error $e ) {
            $line = method_exists( $e, 'getStartLine' ) ? (int) $e->getStartLine() : 0;
            $msg  = trim( $e->getMessage() );
            if ( $line > 0 ) {
                return sprintf( 'PHP Parse error: %s on line %d', $msg, $line );
            }
            return sprintf( 'PHP Parse error: %s', $msg );
        } catch ( \Throwable $e ) {
            $msg = trim( $e->getMessage() );
            return $msg !== '' ? $msg : __( 'Unknown parse error.', 'phpguard-lite' );
        }
    }

    /**
     * Normalize a lint/parse output string so it is safe and stable to display.
     *
     * This strips full server paths and common noisy prefixes.
     *
     * @param string $output Raw output.
     * @param string $file   File path that may be present inside the output.
     * @return string
     */
    protected function normalize_php_lint_output( $output, $file ) {
        if ( ! is_string( $output ) ) {
            return '';
        }

        $out = trim( $output );
        if ( '' === $out ) {
            return '';
        }

        // Remove Windows newlines for consistency.
        $out = str_replace( "\r\n", "\n", $out );

        // Replace the exact file path with a friendly label.
        if ( is_string( $file ) && $file !== '' ) {
            $out = str_replace( $file, basename( $file ), $out );
        }

        // Remove any remaining absolute path fragments (best-effort).
        // If we know the file, replace with its basename; otherwise just strip the path.
        $replacement = ( is_string( $file ) && $file !== '' ) ? basename( $file ) : 'file.php';
        $out         = preg_replace( '#\b(?:/[^\s\r\n:]+)+\.php\b#', $replacement, $out );

        // Trim common prefixes.
        $out = preg_replace( '/^\s*(?:PHP\s+)?(?:Parse|Fatal)\s+error:\s*/i', 'PHP Parse error: ', $out );

        // Collapse whitespace.
        $out = preg_replace( '/[\t ]+/', ' ', $out );
        $out = trim( $out );

        return $out;
    }

    protected function clean_php_error_message( $message ) {
        if ( ! is_string( $message ) ) {
            return $message;
        }

        $message = trim( $message );
        if ( '' === $message ) {
            return $message;
        }

        // Drop any "Errors parsing /path/to/file.php" fragments.
        $message = preg_replace( '/Errors parsing [^\r\n]+/i', '', $message );

        // Shorten "PHP Parse error: ... in /path/to/file.php on line 123"
        // to "PHP Parse error: ... on line 123".
        $message = preg_replace(
            '/^(PHP (?:Parse|Fatal) error:[^\n]*?) in .* on line ([0-9]+)$/i',
            '$1 on line $2',
            $message
        );

        // Collapse excessive whitespace.
        $message = preg_replace( '/\s+/', ' ', $message );

        return trim( $message );
    }

}

new PHPGuard_Preinstall_Plugin();