<?php
/**
 * Plugin Name: Luna Chat — Widget (Client)
 * Description: Floating chat widget + shortcode with conversation logging. Pulls client facts from Visible Light Hub and blends them with AI answers. Includes chat history hydration and Hub-gated REST endpoints.
 * Version:     1.7.0
 * Author:      Visible Light
 * License:     GPLv2 or later
 */

if (!defined('ABSPATH')) exit;

/* ============================================================
 * CONSTANTS & OPTIONS
 * ============================================================ */
if (!defined('LUNA_WIDGET_PLUGIN_VERSION')) define('LUNA_WIDGET_PLUGIN_VERSION', '1.7.0');
if (!defined('LUNA_WIDGET_OPT_COMPOSER_ENABLED')) define('LUNA_WIDGET_OPT_COMPOSER_ENABLED', 'luna_composer_enabled');
if (!defined('LUNA_WIDGET_ASSET_URL')) define('LUNA_WIDGET_ASSET_URL', plugin_dir_url(__FILE__));

function luna_composer_default_prompts() {
  $defaults = array(
    array(
      'label'  => 'What can Luna help me with?',
      'prompt' => "Hey Luna! What can you help me with today?",
    ),
    array(
      'label'  => 'Site health overview',
      'prompt' => 'Can you give me a quick health check of my WordPress site?',
    ),
    array(
      'label'  => 'Pending updates',
      'prompt' => 'Do I have any plugin, theme, or WordPress core updates waiting?',
    ),
    array(
      'label'  => 'Security status',
      'prompt' => 'Is my SSL certificate active and are there any security concerns?',
    ),
    array(
      'label'  => 'Content inventory',
      'prompt' => 'How many pages and posts are on the site right now?',
    ),
    array(
      'label'  => 'Help contact info',
      'prompt' => 'Remind me how someone can contact our team for help.',
    ),
  );

  return apply_filters('luna_composer_default_prompts', $defaults);
}

define('LUNA_WIDGET_OPT_LICENSE',         'luna_widget_license');
define('LUNA_WIDGET_OPT_MODE',            'luna_widget_mode');           // 'shortcode' | 'widget'
define('LUNA_WIDGET_OPT_SETTINGS',        'luna_widget_ui_settings');    // array
define('LUNA_WIDGET_OPT_LICENSE_SERVER',  'luna_widget_license_server'); // hub base URL
define('LUNA_WIDGET_OPT_LAST_PING',       'luna_widget_last_ping');      // array {ts,url,code,err,body}

/* Cache */
define('LUNA_CACHE_PROFILE_TTL',          300); // 5 min

/* Hub endpoints map (your Hub can alias to these) */
$GLOBALS['LUNA_HUB_ENDPOINTS'] = array(
  'profile'  => '/wp-json/vl-hub/v1/profile',   // preferred single profile
  'security' => '/wp-json/vl-hub/v1/security',  // fallback piece
  'content'  => '/wp-json/vl-hub/v1/content',   // fallback piece
  'users'    => '/wp-json/vl-hub/v1/users',     // fallback piece
);

/* ============================================================
 * ACTIVATION / DEACTIVATION
 * ============================================================ */
register_activation_hook(__FILE__, function () {
  if (!get_option(LUNA_WIDGET_OPT_MODE, null)) {
    update_option(LUNA_WIDGET_OPT_MODE, 'widget');
  }
  if (!get_option(LUNA_WIDGET_OPT_SETTINGS, null)) {
    update_option(LUNA_WIDGET_OPT_SETTINGS, array(
      'position'    => 'bottom-right',
      'title'       => 'Luna Chat',
      'avatar_url'  => '',
      'header_text' => "Hi, I'm Luna",
      'sub_text'    => 'How can I help today?',
    ));
  }
  if (!get_option(LUNA_WIDGET_OPT_LICENSE_SERVER, null)) {
    update_option(LUNA_WIDGET_OPT_LICENSE_SERVER, 'https://visiblelight.ai');
  }
  if (get_option(LUNA_WIDGET_OPT_COMPOSER_ENABLED, null) === null) {
    update_option(LUNA_WIDGET_OPT_COMPOSER_ENABLED, '1');
  }
  if (!wp_next_scheduled('luna_widget_heartbeat_event')) {
    wp_schedule_event(time() + 60, 'hourly', 'luna_widget_heartbeat_event');
  }
});

register_deactivation_hook(__FILE__, function () {
  $ts = wp_next_scheduled('luna_widget_heartbeat_event');
  if ($ts) wp_unschedule_event($ts, 'luna_widget_heartbeat_event');
});

/* ============================================================
 * ADMIN MENU (Top-level)
 * ============================================================ */
add_action('admin_menu', function () {
  add_menu_page(
    'Luna Widget',
    'Luna Widget',
    'manage_options',
    'luna-widget',
    'luna_widget_admin_page',
    'dashicons-format-chat',
    64
  );
  add_submenu_page(
    'luna-widget',
    'Compose',
    'Compose',
    'manage_options',
    'luna-widget-compose',
    'luna_widget_compose_admin_page'
  );
  add_submenu_page(
    'luna-widget',
    'Settings',
    'Settings',
    'manage_options',
    'luna-widget',
    'luna_widget_admin_page'
  );
  add_submenu_page(
    'luna-widget',
    'Security',
    'Security',
    'manage_options',
    'luna-widget-security',
    'luna_widget_security_admin_page'
  );
  add_submenu_page(
    'luna-widget',
    'Keywords',
    'Keywords',
    'manage_options',
    'luna-widget-keywords',
    'luna_widget_keywords_admin_page'
  );
  
  // Add JavaScript for keywords page
  add_action('admin_enqueue_scripts', function($hook) {
    if ($hook === 'luna-widget_page_luna-widget-keywords') {
      add_action('admin_footer', 'luna_keywords_admin_scripts');
    }
  });
  add_submenu_page(
    'luna-widget',
    'Analytics',
    'Analytics',
    'manage_options',
    'luna-widget-analytics',
    'luna_widget_analytics_admin_page'
  );
});

/* ============================================================
 * SETTINGS
 * ============================================================ */
add_action('admin_init', function () {
  register_setting('luna_widget_settings', LUNA_WIDGET_OPT_LICENSE, array(
    'type' => 'string',
    'sanitize_callback' => function($v){ return preg_replace('/[^A-Za-z0-9\-\_]/','', (string)$v); },
    'default' => '',
  ));
  register_setting('luna_widget_settings', 'luna_openai_api_key', array(
    'type' => 'string',
    'sanitize_callback' => function($v){ return trim((string)$v); },
    'default' => '',
  ));
  register_setting('luna_widget_settings', LUNA_WIDGET_OPT_LICENSE_SERVER, array(
    'type' => 'string',
    'sanitize_callback' => function($v){
      $v = trim((string)$v);
      if ($v === '') return 'https://visiblelight.ai';
      $v = preg_replace('#/+$#','',$v);
      $v = preg_replace('#^http://#i','https://',$v);
      return esc_url_raw($v);
    },
    'default' => 'https://visiblelight.ai',
  ));
  
  // Security settings
  register_setting('luna_widget_security', 'luna_security_overrides', array(
    'type' => 'array',
    'sanitize_callback' => 'luna_sanitize_security_overrides',
    'default' => array(),
  ));
  register_setting('luna_widget_settings', LUNA_WIDGET_OPT_MODE, array(
    'type' => 'string',
    'sanitize_callback' => function($v){ return in_array($v, array('shortcode','widget'), true) ? $v : 'widget'; },
    'default' => 'widget',
  ));
  register_setting('luna_widget_settings', LUNA_WIDGET_OPT_SETTINGS, array(
    'type' => 'array',
    'sanitize_callback' => function($a){
      $a = is_array($a) ? $a : array();
      $pos = isset($a['position']) ? strtolower((string)$a['position']) : 'bottom-right';
      $valid_positions = array('top-left','top-center','top-right','bottom-left','bottom-center','bottom-right');
      if (!in_array($pos, $valid_positions, true)) $pos = 'bottom-right';
      return array(
        'position'    => $pos,
        'title'       => sanitize_text_field(isset($a['title']) ? $a['title'] : 'Luna Chat'),
        'avatar_url'  => esc_url_raw(isset($a['avatar_url']) ? $a['avatar_url'] : ''),
        'header_text' => sanitize_text_field(isset($a['header_text']) ? $a['header_text'] : "Hi, I'm Luna"),
        'sub_text'    => sanitize_text_field(isset($a['sub_text']) ? $a['sub_text'] : 'How can I help today?'),
      );
    },
    'default' => array(),
  ));

  register_setting('luna_composer_settings', LUNA_WIDGET_OPT_COMPOSER_ENABLED, array(
    'type' => 'string',
    'sanitize_callback' => function($value) {
      return $value === '1' ? '1' : '0';
    },
    'default' => '1',
  ));
});

/* Settings page */
function luna_widget_admin_page(){
  if (!current_user_can('manage_options')) return;
  $mode  = get_option(LUNA_WIDGET_OPT_MODE, 'widget');
  $ui    = get_option(LUNA_WIDGET_OPT_SETTINGS, array());
  $lic   = get_option(LUNA_WIDGET_OPT_LICENSE, '');
  $hub   = luna_widget_hub_base();
  $last  = get_option(LUNA_WIDGET_OPT_LAST_PING, array());
  ?>
  <div class="wrap">
    <h1>Luna Chat — Widget</h1>

    <div class="notice notice-info" style="padding:8px 12px;margin-top:10px;">
      <strong>Hub connection:</strong>
      <?php if (!empty($last['code'])): ?>
        Response <code><?php echo (int)$last['code']; ?></code> at <?php echo esc_html(isset($last['ts']) ? $last['ts'] : ''); ?>.
      <?php else: ?>
        No heartbeat recorded yet.
      <?php endif; ?>
      <div style="margin-top:6px;display:flex;gap:8px;align-items:center;">
        <button type="button" class="button" id="luna-test-activation">Test Activation</button>
        <button type="button" class="button" id="luna-test-heartbeat">Heartbeat Now</button>
        <button type="button" class="button button-primary" id="luna-sync-to-hub">Sync to Hub</button>
        <span style="opacity:.8;">Hub: <?php echo esc_html($hub); ?></span>
      </div>
    </div>

    <form method="post" action="options.php">
      <?php settings_fields('luna_widget_settings'); ?>
      <table class="form-table" role="presentation">
        <tr>
          <th scope="row">Corporate License Code</th>
          <td>
            <input type="text" name="<?php echo esc_attr(LUNA_WIDGET_OPT_LICENSE); ?>" value="<?php echo esc_attr($lic); ?>" class="regular-text code" placeholder="VL-XXXX-XXXX-XXXX" />
            <p class="description">Required for secured Hub data.</p>
          </td>
        </tr>
        <tr>
          <th scope="row">License Server (Hub)</th>
          <td>
            <input type="url" name="<?php echo esc_attr(LUNA_WIDGET_OPT_LICENSE_SERVER); ?>" value="<?php echo esc_url($hub); ?>" class="regular-text code" placeholder="https://visiblelight.ai" />
            <p class="description">HTTPS enforced; trailing slashes removed automatically.</p>
          </td>
        </tr>
        <tr>
          <th scope="row">Embedding mode</th>
          <td>
            <label style="display:block;margin-bottom:.4rem;">
              <input type="radio" name="<?php echo esc_attr(LUNA_WIDGET_OPT_MODE); ?>" value="shortcode" <?php checked($mode, 'shortcode'); ?>>
              Shortcode only (<code>[luna_chat]</code>)
            </label>
            <label>
              <input type="radio" name="<?php echo esc_attr(LUNA_WIDGET_OPT_MODE); ?>" value="widget" <?php checked($mode, 'widget'); ?>>
              Floating chat widget (site-wide)
            </label>
          </td>
        </tr>
        <tr>
          <th scope="row">Widget UI</th>
          <td>
            <label style="display:block;margin:.25rem 0;">
              <span style="display:inline-block;width:140px;">Title</span>
              <input type="text" name="<?php echo esc_attr(LUNA_WIDGET_OPT_SETTINGS); ?>[title]" value="<?php echo esc_attr(isset($ui['title']) ? $ui['title'] : 'Luna Chat'); ?>" />
            </label>
            <label style="display:block;margin:.25rem 0;">
              <span style="display:inline-block;width:140px;">Avatar URL</span>
              <input type="url" name="<?php echo esc_attr(LUNA_WIDGET_OPT_SETTINGS); ?>[avatar_url]" value="<?php echo esc_url(isset($ui['avatar_url']) ? $ui['avatar_url'] : ''); ?>" class="regular-text code" placeholder="https://…/luna.png" />
            </label>
            <label style="display:block;margin:.25rem 0;">
              <span style="display:inline-block;width:140px;">Header text</span>
              <input type="text" name="<?php echo esc_attr(LUNA_WIDGET_OPT_SETTINGS); ?>[header_text]" value="<?php echo esc_attr(isset($ui['header_text']) ? $ui['header_text'] : "Hi, I'm Luna"); ?>" />
            </label>
            <label style="display:block;margin:.25rem 0;">
              <span style="display:inline-block;width:140px;">Sub text</span>
              <input type="text" name="<?php echo esc_attr(LUNA_WIDGET_OPT_SETTINGS); ?>[sub_text]" value="<?php echo esc_attr(isset($ui['sub_text']) ? $ui['sub_text'] : 'How can I help today?'); ?>" />
            </label>
            <label style="display:block;margin:.25rem 0;">
              <span style="display:inline-block;width:140px;">Position</span>
              <?php $pos = isset($ui['position']) ? $ui['position'] : 'bottom-right'; ?>
              <select name="<?php echo esc_attr(LUNA_WIDGET_OPT_SETTINGS); ?>[position]">
                <?php foreach (array('top-left','top-center','top-right','bottom-left','bottom-center','bottom-right') as $p): ?>
                  <option value="<?php echo esc_attr($p); ?>" <?php selected($p, $pos); ?>><?php echo esc_html($p); ?></option>
                <?php endforeach; ?>
              </select>
            </label>
          </td>
        </tr>
        <tr>
          <th scope="row">OpenAI API key</th>
          <td>
            <input type="password" name="luna_openai_api_key"
                   value="<?php echo esc_attr( get_option('luna_openai_api_key','') ); ?>"
                   class="regular-text code" placeholder="sk-..." />
            <p class="description">If present, AI answers are blended with Hub facts. Otherwise, deterministic replies only.</p>
          </td>
        </tr>
      </table>
      <?php submit_button('Save changes'); ?>
    </form>
  </div>

  <script>
    (function(){
      const nonce = '<?php echo wp_create_nonce('wp_rest'); ?>';
      async function call(path){
        try{ await fetch(path, {method:'POST', headers:{'X-WP-Nonce': nonce}}); location.reload(); }
        catch(e){ alert('Request failed. See console.'); console.error(e); }
      }
      document.addEventListener('click', function(e){
        if(e.target && e.target.id==='luna-test-activation'){ e.preventDefault(); call('<?php echo esc_url_raw( rest_url('luna_widget/v1/ping-hub') ); ?>'); }
        if(e.target && e.target.id==='luna-test-heartbeat'){ e.preventDefault(); call('<?php echo esc_url_raw( rest_url('luna_widget/v1/heartbeat-now') ); ?>'); }
        if(e.target && e.target.id==='luna-sync-to-hub'){ e.preventDefault(); call('<?php echo esc_url_raw( rest_url('luna_widget/v1/sync-to-hub') ); ?>'); }
      });
    })();
  </script>
  <?php
}

function luna_widget_compose_admin_page() {
  if (!current_user_can('manage_options')) {
    return;
  }

  $enabled = get_option(LUNA_WIDGET_OPT_COMPOSER_ENABLED, '1') === '1';
  $history = luna_composer_recent_entries(10);
  $canned  = get_posts(array(
    'post_type'        => 'luna_canned_response',
    'post_status'      => 'publish',
    'numberposts'      => 10,
    'orderby'          => array('menu_order' => 'ASC', 'title' => 'ASC'),
    'order'            => 'ASC',
    'suppress_filters' => false,
  ));

  ?>
  <div class="wrap luna-composer-admin">
    <h1>Luna Composer</h1>
    <p class="description">Manage the Luna Composer experience alongside the floating widget without installing additional plugins.</p>

    <form method="post" action="options.php" style="margin-bottom:2rem;">
      <?php settings_fields('luna_composer_settings'); ?>
      <table class="form-table" role="presentation">
        <tr>
          <th scope="row">Status</th>
          <td>
            <label>
              <input type="checkbox" name="<?php echo esc_attr(LUNA_WIDGET_OPT_COMPOSER_ENABLED); ?>" value="1" <?php checked($enabled); ?> />
              <?php esc_html_e('Activate Luna Composer front-end shortcode and REST handling', 'luna'); ?>
            </label>
            <p class="description">When disabled, the shortcode renders a notice and API requests return a friendly deactivation message.</p>
          </td>
        </tr>
        <tr>
          <th scope="row">Shortcode</th>
          <td>
            <code style="font-size:1.1em;">[luna_composer]</code>
            <p class="description">Place this shortcode on any page or post to embed the Composer interface. It automatically shares canned prompts and the same REST endpoint as the Luna widget.</p>
          </td>
        </tr>
      </table>
      <?php submit_button(__('Save Composer Settings', 'luna')); ?>
    </form>

    <h2>Recent Composer History</h2>
    <?php if (!empty($history)) : ?>
      <ol class="luna-composer-history" style="max-width:900px;">
        <?php foreach ($history as $entry) :
          $prompt = get_post_meta($entry->ID, 'prompt', true);
          $answer = get_post_meta($entry->ID, 'answer', true);
          $timestamp = (int) get_post_meta($entry->ID, 'timestamp', true);
          $meta = get_post_meta($entry->ID, 'meta', true);
          $source = is_array($meta) && !empty($meta['source']) ? $meta['source'] : 'unknown';
          $time_display = $timestamp ? date_i18n(get_option('date_format') . ' ' . get_option('time_format'), $timestamp) : get_the_date('', $entry);
          ?>
          <li style="margin-bottom:1.5rem;padding:1rem;border:1px solid #dfe4ea;border-radius:8px;background:#fff;">
            <strong><?php echo esc_html($time_display); ?></strong>
            <div style="margin-top:.5rem;">
              <span style="display:block;font-weight:600;">Prompt:</span>
              <div style="margin-top:.35rem;white-space:pre-wrap;"><?php echo esc_html(wp_trim_words($prompt, 50, '…')); ?></div>
            </div>
            <div style="margin-top:.75rem;">
              <span style="display:block;font-weight:600;">Response (<?php echo esc_html($source); ?>):</span>
              <div style="margin-top:.35rem;white-space:pre-wrap;"><?php echo esc_html(wp_trim_words($answer, 120, '…')); ?></div>
            </div>
            <div style="margin-top:.5rem;font-size:.9em;">
              <a href="<?php echo esc_url(get_edit_post_link($entry->ID)); ?>">View full entry</a>
            </div>
          </li>
        <?php endforeach; ?>
      </ol>
    <?php else : ?>
      <p>No composer history recorded yet.</p>
    <?php endif; ?>

    <h2>Canned Prompts &amp; Responses</h2>
    <?php if (!empty($canned)) : ?>
      <table class="widefat fixed striped" style="max-width:900px;">
        <thead>
          <tr>
            <th scope="col">Prompt</th>
            <th scope="col" style="width:35%;">Response preview</th>
            <th scope="col" style="width:120px;">Actions</th>
          </tr>
        </thead>
        <tbody>
          <?php foreach ($canned as $post) :
            $content = luna_widget_prepare_canned_response_content($post->post_content);
            ?>
            <tr>
              <td><?php echo esc_html($post->post_title); ?></td>
              <td><?php echo esc_html(wp_trim_words($content, 30, '…')); ?></td>
              <td><a href="<?php echo esc_url(get_edit_post_link($post->ID)); ?>">Edit</a></td>
            </tr>
          <?php endforeach; ?>
        </tbody>
      </table>
      <p style="margin-top:1rem;"><a class="button" href="<?php echo esc_url(admin_url('edit.php?post_type=luna_canned_response')); ?>">Manage canned responses</a></p>
    <?php else : ?>
      <p>No canned responses found. <a href="<?php echo esc_url(admin_url('post-new.php?post_type=luna_canned_response')); ?>">Create your first canned response</a> to provide offline answers when the Hub is unavailable.</p>
    <?php endif; ?>
  </div>
  <?php
}

/* ============================================================
 * SECURITY ADMIN PAGE
 * ============================================================ */
function luna_widget_security_admin_page() {
  if (!current_user_can('manage_options')) return;

  // Save on post
  if ($_SERVER['REQUEST_METHOD'] === 'POST' && check_admin_referer('luna_widget_save_security')) {
    $in = array(
      'tls' => array(
        'valid'          => isset($_POST['tls_valid']) ? (bool)$_POST['tls_valid'] : null,
        'version'        => sanitize_text_field($_POST['tls_version'] ?? ''),
        'issuer'         => sanitize_text_field($_POST['tls_issuer'] ?? ''),
        'provider_guess' => sanitize_text_field($_POST['tls_provider_guess'] ?? ''),
        'valid_from'     => sanitize_text_field($_POST['tls_valid_from'] ?? ''),
        'valid_to'       => sanitize_text_field($_POST['tls_valid_to'] ?? ''),
        'days_remaining' => sanitize_text_field($_POST['tls_days_remaining'] ?? ''),
        'host'           => sanitize_text_field($_POST['tls_host'] ?? ''),
      ),
      'waf' => array(
        'provider'   => sanitize_text_field($_POST['waf_provider'] ?? ''),
        'last_audit' => sanitize_text_field($_POST['waf_last_audit'] ?? ''),
        'rulesets'   => sanitize_textarea_field($_POST['waf_rulesets'] ?? ''),
      ),
      'ids' => array(
        'provider'   => sanitize_text_field($_POST['ids_provider'] ?? ''),
        'last_scan'  => sanitize_text_field($_POST['ids_last_scan'] ?? ''),
        'result'     => sanitize_text_field($_POST['ids_result'] ?? ''),
        'schedule'   => sanitize_text_field($_POST['ids_schedule'] ?? ''),
      ),
      'auth' => array(
        'mfa'             => sanitize_text_field($_POST['auth_mfa'] ?? ''),
        'password_policy' => sanitize_text_field($_POST['auth_password_policy'] ?? ''),
        'session_timeout' => sanitize_text_field($_POST['auth_session_timeout'] ?? ''),
        'sso_providers'   => sanitize_text_field($_POST['auth_sso_providers'] ?? ''),
      ),
      'domain' => array(
        'domain'        => sanitize_text_field($_POST['domain_domain'] ?? ''),
        'registrar'     => sanitize_text_field($_POST['domain_registrar'] ?? ''),
        'registered_on' => sanitize_text_field($_POST['domain_registered_on'] ?? ''),
        'renewal_date'  => sanitize_text_field($_POST['domain_renewal_date'] ?? ''),
        'auto_renew'    => sanitize_text_field($_POST['domain_auto_renew'] ?? ''),
        'dns_records'   => wp_kses_post($_POST['domain_dns_records'] ?? ''),
      ),
    );
    update_option('luna_security_overrides', $in);
    
    // Send to Hub
    luna_send_security_to_hub($in);
    
    echo '<div class="updated"><p>Security data saved and sent to Visible Light Hub.</p></div>';
  }

  $ov = get_option('luna_security_overrides', array());
  ?>
  <div class="wrap">
    <h1>Luna Security</h1>
    <p>Enter your security information. This data will be sent to Visible Light Hub and used by Luna AI to answer security-related questions.</p>

    <form method="post" action="">
      <?php wp_nonce_field('luna_widget_save_security'); ?>

      <h2>TLS / SSL</h2>
      <table class="form-table" role="presentation">
        <tr><th scope="row">Valid</th><td><label><input type="checkbox" name="tls_valid" value="1" <?php checked(!empty($ov['tls']['valid'])); ?>> Site has a valid certificate</label></td></tr>
        <tr><th scope="row">TLS Version</th><td><input type="text" name="tls_version" class="regular-text" value="<?php echo esc_attr($ov['tls']['version'] ?? ''); ?>"></td></tr>
        <tr><th scope="row">Issuer</th><td><input type="text" name="tls_issuer" class="regular-text" value="<?php echo esc_attr($ov['tls']['issuer'] ?? ''); ?>"></td></tr>
        <tr><th scope="row">Provider (guess)</th><td><input type="text" name="tls_provider_guess" class="regular-text" value="<?php echo esc_attr($ov['tls']['provider_guess'] ?? ''); ?>"></td></tr>
        <tr><th scope="row">Valid From</th><td><input type="text" name="tls_valid_from" class="regular-text" value="<?php echo esc_attr($ov['tls']['valid_from'] ?? ''); ?>"></td></tr>
        <tr><th scope="row">Valid To</th><td><input type="text" name="tls_valid_to" class="regular-text" value="<?php echo esc_attr($ov['tls']['valid_to'] ?? ''); ?>"></td></tr>
        <tr><th scope="row">Days Remaining</th><td><input type="text" name="tls_days_remaining" class="regular-text" value="<?php echo esc_attr($ov['tls']['days_remaining'] ?? ''); ?>"></td></tr>
        <tr><th scope="row">Host</th><td><input type="text" name="tls_host" class="regular-text" value="<?php echo esc_attr($ov['tls']['host'] ?? ''); ?>"></td></tr>
      </table>

      <h2>Firewall / WAF</h2>
      <table class="form-table" role="presentation">
        <tr><th scope="row">Provider</th><td><input type="text" name="waf_provider" class="regular-text" value="<?php echo esc_attr($ov['waf']['provider'] ?? ''); ?>"></td></tr>
        <tr><th scope="row">Last Audit</th><td><input type="text" name="waf_last_audit" class="regular-text" value="<?php echo esc_attr($ov['waf']['last_audit'] ?? ''); ?>"></td></tr>
        <tr><th scope="row">Rulesets</th><td><textarea name="waf_rulesets" class="large-text" rows="3"><?php echo esc_textarea($ov['waf']['rulesets'] ?? ''); ?></textarea></td></tr>
      </table>

      <h2>Threat Detection / IDS</h2>
      <table class="form-table" role="presentation">
        <tr><th scope="row">Provider</th><td><input type="text" name="ids_provider" class="regular-text" value="<?php echo esc_attr($ov['ids']['provider'] ?? ''); ?>"></td></tr>
        <tr><th scope="row">Last Scan</th><td><input type="text" name="ids_last_scan" class="regular-text" value="<?php echo esc_attr($ov['ids']['last_scan'] ?? ''); ?>"></td></tr>
        <tr><th scope="row">Last Result</th><td><input type="text" name="ids_result" class="regular-text" value="<?php echo esc_attr($ov['ids']['result'] ?? ''); ?>"></td></tr>
        <tr><th scope="row">Scan Schedule</th><td><input type="text" name="ids_schedule" class="regular-text" value="<?php echo esc_attr($ov['ids']['schedule'] ?? ''); ?>"></td></tr>
      </table>

      <h2>Authentication</h2>
      <table class="form-table" role="presentation">
        <tr><th scope="row">MFA</th><td><input type="text" name="auth_mfa" class="regular-text" value="<?php echo esc_attr($ov['auth']['mfa'] ?? ''); ?>"></td></tr>
        <tr><th scope="row">Password Policy</th><td><input type="text" name="auth_password_policy" class="regular-text" value="<?php echo esc_attr($ov['auth']['password_policy'] ?? ''); ?>"></td></tr>
        <tr><th scope="row">Session Timeout</th><td><input type="text" name="auth_session_timeout" class="regular-text" value="<?php echo esc_attr($ov['auth']['session_timeout'] ?? ''); ?>"></td></tr>
        <tr><th scope="row">SSO Providers</th><td><input type="text" name="auth_sso_providers" class="regular-text" value="<?php echo esc_attr($ov['auth']['sso_providers'] ?? ''); ?>"></td></tr>
      </table>

      <h2>Domain</h2>
      <table class="form-table" role="presentation">
        <tr><th scope="row">Domain</th><td><input type="text" name="domain_domain" class="regular-text" value="<?php echo esc_attr($ov['domain']['domain'] ?? ''); ?>"></td></tr>
        <tr><th scope="row">Registrar</th><td><input type="text" name="domain_registrar" class="regular-text" value="<?php echo esc_attr($ov['domain']['registrar'] ?? ''); ?>"></td></tr>
        <tr><th scope="row">Registered On</th><td><input type="text" name="domain_registered_on" class="regular-text" value="<?php echo esc_attr($ov['domain']['registered_on'] ?? ''); ?>"></td></tr>
        <tr><th scope="row">Renewal Date</th><td><input type="text" name="domain_renewal_date" class="regular-text" value="<?php echo esc_attr($ov['domain']['renewal_date'] ?? ''); ?>"></td></tr>
        <tr><th scope="row">Auto Renew</th><td><input type="text" name="domain_auto_renew" class="regular-text" value="<?php echo esc_attr($ov['domain']['auto_renew'] ?? ''); ?>"></td></tr>
        <tr><th scope="row">DNS Records (freeform)</th><td><textarea name="domain_dns_records" class="large-text" rows="5"><?php echo esc_textarea($ov['domain']['dns_records'] ?? ''); ?></textarea></td></tr>
      </table>

      <?php submit_button('Save Security Data'); ?>
    </form>
  </div>
  <?php
}

/* ============================================================
 * SECURITY FUNCTIONS
 * ============================================================ */
function luna_sanitize_security_overrides($val) {
  $defaults = array(
    'tls' => array('valid' => null, 'version' => '', 'issuer' => '', 'provider_guess' => '', 'valid_from' => '', 'valid_to' => '', 'days_remaining' => '', 'host' => ''),
    'waf' => array('provider' => '', 'last_audit' => '', 'rulesets' => ''),
    'ids' => array('provider' => '', 'last_scan' => '', 'result' => '', 'schedule' => ''),
    'auth' => array('mfa' => '', 'password_policy' => '', 'session_timeout' => '', 'sso_providers' => ''),
    'domain' => array('domain' => '', 'registrar' => '', 'registered_on' => '', 'renewal_date' => '', 'auto_renew' => '', 'dns_records' => ''),
  );
  $val = is_array($val) ? $val : array();
  return array_replace_recursive($defaults, $val);
}

function luna_send_security_to_hub($overrides) {
  $license = get_option(LUNA_WIDGET_OPT_LICENSE, '');
  if (!$license) return false;
  
  $payload = array(
    'security' => $overrides,
  );
  
  // Debug logging
  error_log('[Luna Client] Sending security data to Hub: ' . print_r($payload, true));
  
  $url = luna_widget_hub_url('/wp-json/vl-hub/v1/profile/security?license=' . rawurlencode($license));
  $resp = wp_remote_post($url, array(
    'timeout' => 20,
    'headers' => array(
      'Content-Type' => 'application/json',
      'X-Luna-License' => $license,
      'X-Luna-Site' => home_url('/'),
    ),
    'body' => wp_json_encode($payload),
  ));
  
  if (is_wp_error($resp)) {
    error_log('[Luna Widget] Security sync failed: ' . $resp->get_error_message());
    return false;
  }
  
  $code = wp_remote_retrieve_response_code($resp);
  $body = wp_remote_retrieve_body($resp);
  
  error_log('[Luna Widget] Security sync response: HTTP ' . $code . ' - ' . $body);
  
  if ($code >= 400) {
    error_log('[Luna Widget] Security sync failed: HTTP ' . $code);
    return false;
  }
  
  return true;
}

/* ============================================================
 * HEARTBEAT / HUB HELPERS
 * ============================================================ */
function luna_widget_hub_base() {
  $base = (string) get_option(LUNA_WIDGET_OPT_LICENSE_SERVER, 'https://visiblelight.ai');
  $base = preg_replace('#/+$#','',$base);
  $base = preg_replace('#^http://#i','https://',$base);
  return $base ? $base : 'https://visiblelight.ai';
}
function luna_widget_hub_url($path = '') {
  $path = '/'.ltrim($path,'/');
  return luna_widget_hub_base() . $path;
}
function luna_widget_store_last_ping($url, $resp) {
  $log = array(
    'ts'   => gmdate('c'),
    'url'  => $url,
    'code' => is_wp_error($resp) ? 0 : (int) wp_remote_retrieve_response_code($resp),
    'err'  => is_wp_error($resp) ? $resp->get_error_message() : '',
    'body' => is_wp_error($resp) ? '' : substr((string) wp_remote_retrieve_body($resp), 0, 500),
  );
  update_option(LUNA_WIDGET_OPT_LAST_PING, $log, false);
}
function luna_widget_try_activation() {
  $license = trim((string) get_option(LUNA_WIDGET_OPT_LICENSE, ''));
  if ($license === '') return;
  $body = array(
    'license'        => $license,
    'site_url'       => home_url('/'),
    'site_name'      => get_bloginfo('name'),
    'wp_version'     => get_bloginfo('version'),
    'plugin_version' => LUNA_WIDGET_PLUGIN_VERSION,
  );
  $url = luna_widget_hub_url('/wp-json/vl-license/v1/activate');
  $resp = wp_remote_post($url, array(
    'timeout' => 15,
    'headers' => array(
      'Content-Type'   => 'application/json',
      'X-Luna-License' => $license,
      'X-Luna-Site'    => home_url('/'),
    ),
    'body'    => wp_json_encode($body),
  ));
  luna_widget_store_last_ping($url, $resp);
}
function luna_widget_send_heartbeat() {
  $license = trim((string) get_option(LUNA_WIDGET_OPT_LICENSE, ''));
  if ($license === '') return;
  $body = array(
    'license'        => $license,
    'site_url'       => home_url('/'),
    'wp_version'     => get_bloginfo('version'),
    'plugin_version' => LUNA_WIDGET_PLUGIN_VERSION,
  );
  $url  = luna_widget_hub_url('/wp-json/vl-license/v1/heartbeat');
  $resp = wp_remote_post($url, array(
    'timeout' => 15,
    'headers' => array(
      'Content-Type'   => 'application/json',
      'X-Luna-License' => $license,
      'X-Luna-Site'    => home_url('/'),
    ),
    'body'    => wp_json_encode($body),
  ));
  luna_widget_store_last_ping($url, $resp);
}
add_action('luna_widget_heartbeat_event', function () {
  if (!wp_next_scheduled('luna_widget_heartbeat_event')) {
    wp_schedule_event(time() + 3600, 'hourly', 'luna_widget_heartbeat_event');
  }
  luna_widget_send_heartbeat();
});
add_action('update_option_' . LUNA_WIDGET_OPT_LICENSE, function($old, $new){
  if ($new && $new !== $old) { luna_widget_try_activation(); luna_widget_send_heartbeat(); luna_profile_cache_bust(true); }
}, 10, 2);
add_action('update_option_' . LUNA_WIDGET_OPT_LICENSE_SERVER, function($old, $new){
  if ($new && $new !== $old) { luna_widget_try_activation(); luna_widget_send_heartbeat(); luna_profile_cache_bust(true); }
}, 10, 2);

/* ============================================================
 * CONVERSATIONS: CPT + helpers
 * ============================================================ */
add_action('init', function () {
  register_post_type('luna_widget_convo', array(
    'label'        => 'Luna Conversations',
    'public'       => false,
    'show_ui'      => true,
    'show_in_menu' => false,
    'supports'     => array('title'),
    'map_meta_cap' => true,
  ));
});

/* ============================================================
 * COMPOSER ENTRIES CPT (history)
 * ============================================================ */
add_action('init', function () {
  $labels = array(
    'name'          => __('Compose', 'luna'),
    'singular_name' => __('Compose Entry', 'luna'),
  );

  register_post_type('luna_compose', array(
    'labels'              => $labels,
    'public'              => false,
    'show_ui'             => false,
    'show_in_menu'        => false,
    'capability_type'     => 'post',
    'map_meta_cap'        => true,
    'supports'            => array('title'),
  ));
});

/* ============================================================
 * CANNED RESPONSES FALLBACK
 * ============================================================ */
add_action('init', function () {
  $labels = array(
    'name'               => __('Canned Responses', 'luna'),
    'singular_name'      => __('Canned Response', 'luna'),
    'add_new'            => __('Add New', 'luna'),
    'add_new_item'       => __('Add New Canned Response', 'luna'),
    'edit_item'          => __('Edit Canned Response', 'luna'),
    'new_item'           => __('New Canned Response', 'luna'),
    'view_item'          => __('View Canned Response', 'luna'),
    'search_items'       => __('Search Canned Responses', 'luna'),
    'not_found'          => __('No canned responses found.', 'luna'),
    'not_found_in_trash' => __('No canned responses found in Trash.', 'luna'),
    'menu_name'          => __('Canned Responses', 'luna'),
  );

  register_post_type('luna_canned_response', array(
    'labels'              => $labels,
    'public'              => false,
    'show_ui'             => true,
    'show_in_menu'        => 'luna-widget',
    'show_in_rest'        => true,
    'capability_type'     => 'post',
    'map_meta_cap'        => true,
    'supports'            => array('title', 'editor', 'revisions'),
    'menu_icon'           => 'dashicons-text-page',
    'menu_position'       => 26,
  ));
});

function luna_widget_normalize_prompt_text($value) {
  $value = is_string($value) ? $value : '';
  $value = wp_strip_all_tags($value);
  $value = html_entity_decode($value, ENT_QUOTES, get_option('blog_charset', 'UTF-8'));
  $value = preg_replace('/\s+/u', ' ', $value);
  return trim($value);
}

function luna_widget_prepare_canned_response_content($content) {
  $content = (string) apply_filters('the_content', $content);
  $content = str_replace(array("\r\n", "\r"), "\n", $content);
  $content = preg_replace('/<\s*br\s*\/?\s*>/i', "\n", $content);
  $content = preg_replace('/<\/(p|div|li|h[1-6])\s*>/i', '</$1>\n\n', $content);
  $content = wp_strip_all_tags($content);
  $content = html_entity_decode($content, ENT_QUOTES, get_option('blog_charset', 'UTF-8'));
  $content = preg_replace("/\n{3,}/", "\n\n", $content);
  return trim($content);
}

function luna_widget_find_canned_response($prompt) {
  $normalized = luna_widget_normalize_prompt_text($prompt);
  if ($normalized === '') {
    return null;
  }

  $posts = get_posts(array(
    'post_type'        => 'luna_canned_response',
    'post_status'      => 'publish',
    'numberposts'      => -1,
    'orderby'          => array('menu_order' => 'ASC', 'title' => 'ASC'),
    'order'            => 'ASC',
    'suppress_filters' => false,
  ));

  if (empty($posts)) {
    return null;
  }

  $normalized_lc = function_exists('mb_strtolower') ? mb_strtolower($normalized, 'UTF-8') : strtolower($normalized);
  $best = null;
  $best_score = 0.0;

  foreach ($posts as $post) {
    $title_normalized = luna_widget_normalize_prompt_text($post->post_title);
    if ($title_normalized === '') {
      continue;
    }
    $title_lc = function_exists('mb_strtolower') ? mb_strtolower($title_normalized, 'UTF-8') : strtolower($title_normalized);

    if ($title_lc === $normalized_lc) {
      return array(
        'id'      => $post->ID,
        'title'   => $post->post_title,
        'content' => luna_widget_prepare_canned_response_content($post->post_content),
      );
    }

    $score = 0.0;
    if (function_exists('similar_text')) {
      similar_text($normalized_lc, $title_lc, $percent);
      $score = (float) $percent;
    } elseif (function_exists('levenshtein')) {
      $distance = levenshtein($normalized_lc, $title_lc);
      $max_len = max(strlen($normalized_lc), strlen($title_lc), 1);
      $score = 100.0 - (min($distance, $max_len) / $max_len * 100.0);
    } else {
      $score = strpos($normalized_lc, $title_lc) !== false || strpos($title_lc, $normalized_lc) !== false ? 100.0 : 0.0;
    }

    if ($score > $best_score) {
      $best_score = $score;
      $best = $post;
    }
  }

  if ($best && $best_score >= 55.0) {
    return array(
      'id'      => $best->ID,
      'title'   => $best->post_title,
      'content' => luna_widget_prepare_canned_response_content($best->post_content),
    );
  }

  return null;
}

function luna_widget_create_conversation_post($cid) {
  $pid = wp_insert_post(array(
    'post_type'   => 'luna_widget_convo',
    'post_title'  => 'Conversation ' . substr($cid, 0, 8),
    'post_status' => 'publish',
  ));
  if ($pid && !is_wp_error($pid)) {
    update_post_meta($pid, 'luna_cid', $cid);
    update_post_meta($pid, 'transcript', array());
    return (int)$pid;
  }
  return 0;
}

function luna_widget_current_conversation_id() {
  $cookie_key = 'luna_widget_cid';
  if (empty($_COOKIE[$cookie_key])) {
    return 0;
  }
  $cid = sanitize_text_field(wp_unslash($_COOKIE[$cookie_key]));
  if ($cid === '') {
    return 0;
  }
  $existing = get_posts(array(
    'post_type'   => 'luna_widget_convo',
    'meta_key'    => 'luna_cid',
    'meta_value'  => $cid,
    'fields'      => 'ids',
    'numberposts' => 1,
    'post_status' => 'any',
  ));
  return $existing ? (int)$existing[0] : 0;
}

function luna_conv_id($force_new = false) {
  $cookie_key = 'luna_widget_cid';
  $cid = isset($_COOKIE[$cookie_key]) ? sanitize_text_field(wp_unslash($_COOKIE[$cookie_key])) : '';

  if (!$force_new) {
    $pid = luna_widget_current_conversation_id();
    if ($pid) return $pid;
    if ($cid !== '') {
      @setcookie($cookie_key, $cid, 0, COOKIEPATH ? COOKIEPATH : '/', COOKIE_DOMAIN ? COOKIE_DOMAIN : '', is_ssl(), true);
      $_COOKIE[$cookie_key] = $cid;
      return luna_widget_create_conversation_post($cid);
    }
  }

  $cid = 'lwc_' . uniqid('', true);
  @setcookie($cookie_key, $cid, 0, COOKIEPATH ? COOKIEPATH : '/', COOKIE_DOMAIN ? COOKIE_DOMAIN : '', is_ssl(), true);
  $_COOKIE[$cookie_key] = $cid;
  return luna_widget_create_conversation_post($cid);
}

function luna_widget_close_conversation($pid, $reason = '') {
  if (!$pid) return;
  update_post_meta($pid, 'session_closed', time());
  if ($reason !== '') {
    update_post_meta($pid, 'session_closed_reason', sanitize_text_field($reason));
  }
}
function luna_log_turn($user, $assistant, $meta = array()) {
  $pid = luna_conv_id(); if (!$pid) return;
  $t = get_post_meta($pid, 'transcript', true);
  if (!is_array($t)) $t = array();
  $t[] = array('ts'=>time(), 'user'=>$user, 'assistant'=>$assistant, 'meta'=>$meta);
  update_post_meta($pid, 'transcript', $t);

  // Also log to Hub
  luna_log_conversation_to_hub($t);
}

function luna_composer_log_entry($prompt, $answer, $meta = array(), $conversation_id = 0) {
  $prompt = trim(wp_strip_all_tags((string) $prompt));
  $answer = trim((string) $answer);
  if ($prompt === '' && $answer === '') {
    return 0;
  }

  $title = $prompt !== '' ? wp_trim_words($prompt, 12, '…') : __('Composer Entry', 'luna');
  $post_id = wp_insert_post(array(
    'post_type'   => 'luna_compose',
    'post_title'  => $title,
    'post_status' => 'publish',
  ));

  if (!$post_id || is_wp_error($post_id)) {
    return 0;
  }

  update_post_meta($post_id, 'prompt', $prompt);
  update_post_meta($post_id, 'answer', $answer);
  update_post_meta($post_id, 'meta', is_array($meta) ? $meta : array());
  if ($conversation_id) {
    update_post_meta($post_id, 'conversation_post', (int) $conversation_id);
  }
  update_post_meta($post_id, 'timestamp', time());

  return (int) $post_id;
}

function luna_composer_recent_entries($limit = 10) {
  $query = new WP_Query(array(
    'post_type'      => 'luna_compose',
    'post_status'    => 'publish',
    'posts_per_page' => max(1, (int) $limit),
    'orderby'        => 'date',
    'order'          => 'DESC',
    'no_found_rows'  => true,
  ));

  $posts = $query->posts;
  wp_reset_postdata();
  return $posts;
}

/* Log conversation to Hub */
function luna_log_conversation_to_hub($transcript) {
  $license = luna_get_license();
  if (!$license) {
    error_log('Luna Hub Log: No license found');
    return false;
  }
  
  $hub_url = luna_widget_hub_base();
  $conversation_data = array(
    'id' => 'conv_' . uniqid('', true),
    'started_at' => !empty($transcript[0]['ts']) ? gmdate('c', (int)$transcript[0]['ts']) : gmdate('c'),
    'transcript' => $transcript
  );
  
  error_log('Luna Hub Log: Sending conversation to Hub: ' . print_r($conversation_data, true));
  
  $response = wp_remote_post($hub_url . '/wp-json/luna_widget/v1/conversations/log', array(
    'headers' => array(
      'X-Luna-License' => $license,
      'Content-Type' => 'application/json'
    ),
    'body' => wp_json_encode($conversation_data),
    'timeout' => 10
  ));
  
  if (is_wp_error($response)) {
    error_log('Luna Hub Log: Error sending to Hub: ' . $response->get_error_message());
    return false;
  }
  
  $response_code = wp_remote_retrieve_response_code($response);
  $response_body = wp_remote_retrieve_body($response);
  
  error_log('Luna Hub Log: Hub response code: ' . $response_code);
  error_log('Luna Hub Log: Hub response body: ' . $response_body);
  
  return $response_code >= 200 && $response_code < 300;
}

/* ============================================================
 * HUB PROFILE FETCH (LICENSE-GATED) + FACTS
 * ============================================================ */
function luna_get_license() { return trim((string) get_option(LUNA_WIDGET_OPT_LICENSE, '')); }

function luna_profile_cache_key() {
  $license = luna_get_license();
  $hub     = luna_widget_hub_base();
  $site    = home_url('/');
  return 'luna_profile_' . md5($license . '|' . $hub . '|' . $site);
}
function luna_profile_cache_bust($all=false){
  // Single-site cache key; $all kept for API symmetry
  delete_transient( luna_profile_cache_key() );
  if ($all) {
    delete_transient( luna_hub_collections_cache_key() );
  }
}

function luna_hub_normalize_payload($payload) {
  if (!is_array($payload)) {
    return $payload;
  }

  if (isset($payload['data']) && is_array($payload['data'])) {
    $payload = $payload['data'];
  } elseif (isset($payload['profile']) && is_array($payload['profile'])) {
    $payload = $payload['profile'];
  } elseif (isset($payload['payload']) && is_array($payload['payload'])) {
    $payload = $payload['payload'];
  }

  return $payload;
}

function luna_hub_get_json($path) {
  $license = luna_get_license();
  if ($license === '') return null;
  
  // Add license parameter to URL if not already present
  $url = luna_widget_hub_url($path);
  if (strpos($url, '?') !== false) {
    $url .= '&license=' . rawurlencode($license);
  } else {
    $url .= '?license=' . rawurlencode($license);
  }
  
  $resp = wp_remote_get($url, array(
    'timeout' => 12,
    'headers' => array(
      'X-Luna-License' => $license,
      'X-Luna-Site'    => home_url('/'),
      'Accept'         => 'application/json'
    ),
    'sslverify' => true,
  ));
  if (is_wp_error($resp)) return null;
  $code = (int) wp_remote_retrieve_response_code($resp);
  if ($code >= 400) return null;
  $body = json_decode(wp_remote_retrieve_body($resp), true);
  return is_array($body) ? $body : null;
}

function luna_hub_profile() {
  if (isset($_GET['luna_profile_nocache'])) luna_profile_cache_bust();
  $key = luna_profile_cache_key();
  $cached = get_transient($key);
  if (is_array($cached)) return $cached;

  $map = isset($GLOBALS['LUNA_HUB_ENDPOINTS']) ? $GLOBALS['LUNA_HUB_ENDPOINTS'] : array();
  $profile = luna_hub_get_json(isset($map['profile']) ? $map['profile'] : '/wp-json/vl-hub/v1/profile');
  if (is_array($profile)) {
    $profile = luna_hub_normalize_payload($profile);
  }

  if (!$profile) {
    // Fallback to local data only if Hub profile is not available
    $profile = array(
      'site'      => array('url' => home_url('/')),
      'wordpress' => array('version' => get_bloginfo('version')),
      'security'  => array(),
      'content'   => array(),
      'users'     => array(),
    );
  }

  set_transient($key, $profile, LUNA_CACHE_PROFILE_TTL);
  return $profile;
}

function luna_hub_collections_cache_key() {
  $license = luna_get_license();
  $hub     = luna_widget_hub_base();
  return 'luna_hub_collections_' . md5($license . '|' . $hub);
}

function luna_hub_fetch_first_json($paths) {
  if (!is_array($paths)) {
    $paths = array($paths);
  }

  foreach ($paths as $path) {
    $payload = luna_hub_get_json($path);
    if (is_array($payload)) {
      $normalized = luna_hub_normalize_payload($payload);
      if (is_array($normalized) && !empty($normalized)) {
        return $normalized;
      }
    }
  }

  return null;
}

function luna_hub_collect_collections($force_refresh = false, $prefetched = array()) {
  $license = luna_get_license();
  if ($license === '') {
    return array();
  }

  $key = luna_hub_collections_cache_key();
  if (!$force_refresh) {
    $cached = get_transient($key);
    if (is_array($cached)) {
      if (is_array($prefetched) && !empty($prefetched)) {
        $updated = false;
        foreach ($prefetched as $pref_key => $pref_value) {
          if (is_array($pref_value) && !empty($pref_value) && (!isset($cached[$pref_key]) || $cached[$pref_key] !== $pref_value)) {
            $cached[$pref_key] = $pref_value;
            $updated = true;
          }
        }
        if ($updated) {
          if (!isset($cached['_meta']) || !is_array($cached['_meta'])) {
            $cached['_meta'] = array();
          }
          $cached['_meta']['retrieved_at'] = gmdate('c');
          $cached['_meta']['categories'] = isset($cached['_meta']['categories']) ? $cached['_meta']['categories'] : array_keys(array_diff_key($cached, array('_meta' => true)));
          set_transient($key, $cached, LUNA_CACHE_PROFILE_TTL);
        }
      }
      return $cached;
    }
  }

  $categories = array(
    'profile'      => array('/wp-json/vl-hub/v1/profile', '/wp-json/luna_widget/v1/system/comprehensive'),
    'connections'  => array('/wp-json/vl-hub/v1/connections', '/wp-json/vl-hub/v1/all-connections', '/wp-json/vl-hub/v1/data-sources'),
    'cloudops'     => array('/wp-json/vl-hub/v1/cloudops', '/wp-json/vl-hub/v1/cloud-ops'),
    'content'      => array('/wp-json/vl-hub/v1/content'),
    'search'       => array('/wp-json/vl-hub/v1/search', '/wp-json/vl-hub/v1/search-console'),
    'analytics'    => array('/wp-json/vl-hub/v1/analytics', '/wp-json/vl-hub/v1/ga4'),
    'marketing'    => array('/wp-json/vl-hub/v1/marketing'),
    'ecommerce'    => array('/wp-json/vl-hub/v1/ecommerce', '/wp-json/vl-hub/v1/e-commerce'),
    'security'     => array('/wp-json/vl-hub/v1/security'),
    'web_infra'    => array('/wp-json/vl-hub/v1/web-infra', '/wp-json/vl-hub/v1/web-infrastructure', '/wp-json/vl-hub/v1/infra'),
    'identity'     => array('/wp-json/vl-hub/v1/identity'),
    'competitive'  => array('/wp-json/vl-hub/v1/competitive', '/wp-json/vl-hub/v1/competition', '/wp-json/vl-hub/v1/competitors'),
    'users'        => array('/wp-json/vl-hub/v1/users'),
    'plugins'      => array('/wp-json/vl-hub/v1/plugins'),
    'themes'       => array('/wp-json/vl-hub/v1/themes'),
    'updates'      => array('/wp-json/vl-hub/v1/updates'),
  );

  $collections = array();

  if (is_array($prefetched) && !empty($prefetched)) {
    foreach ($prefetched as $pref_key => $pref_value) {
      if (is_array($pref_value) && !empty($pref_value)) {
        $collections[$pref_key] = $pref_value;
      }
    }
  }

  foreach ($categories as $name => $paths) {
    if (isset($collections[$name]) && is_array($collections[$name])) {
      continue;
    }
    $data = luna_hub_fetch_first_json($paths);
    if ($data !== null) {
      $collections[$name] = $data;
    }
  }

  $streams = luna_fetch_hub_data_streams($license);
  if (is_array($streams) && !empty($streams)) {
    $collections['data_streams'] = $streams;
  }

  $collections['_meta'] = array(
    'retrieved_at' => gmdate('c'),
    'license'      => $license,
    'categories'   => array_keys(array_diff_key($collections, array('_meta' => true))),
  );

  set_transient($key, $collections, LUNA_CACHE_PROFILE_TTL);

  return $collections;
}

/* Helpers to normalize Hub data and provide local fallbacks */
function luna_is_list_array($value) {
  if (!is_array($value)) return false;
  if ($value === array()) return true;
  return array_keys($value) === range(0, count($value) - 1);
}

function luna_extract_hub_items($payload, $key) {
  if (!is_array($payload)) return null;

  $sources = array();
  if (isset($payload[$key])) {
    $sources[] = $payload[$key];
  }

  $underscored = '_' . $key;
  if (isset($payload[$underscored])) {
    $sources[] = $payload[$underscored];
  }

  if (isset($payload['content']) && is_array($payload['content']) && isset($payload['content'][$key])) {
    $sources[] = $payload['content'][$key];
  }

  foreach ($sources as $source) {
    if (!is_array($source)) {
      continue;
    }

    if (isset($source['items']) && is_array($source['items'])) {
      return $source['items'];
    }

    if (luna_is_list_array($source)) {
      return $source;
    }
  }

  return null;
}

function luna_collect_local_post_type_snapshot($post_type, $limit = 25) {
  $post_type = sanitize_key($post_type);
  if (!$post_type) return array();

  $ids = get_posts(array(
    'post_type'       => $post_type,
    'post_status'     => array('publish','draft','pending','private'),
    'numberposts'     => $limit,
    'orderby'         => 'date',
    'order'           => 'DESC',
    'fields'          => 'ids',
    'suppress_filters'=> true,
  ));

  if (!is_array($ids)) return array();

  $items = array();
  foreach ($ids as $pid) {
    $items[] = array(
      'id'        => (int) $pid,
      'title'     => get_the_title($pid),
      'slug'      => get_post_field('post_name', $pid),
      'status'    => get_post_status($pid),
      'date'      => get_post_time('c', true, $pid),
      'permalink' => get_permalink($pid),
    );
  }

  return $items;
}

/* Build compact facts, prioritizing Hub over local snapshot; no network/probe overrides */
function luna_profile_facts() {
  $hub     = luna_hub_profile();
  $local   = luna_snapshot_system(); // fallback only
  $license = luna_get_license();

  $site_url = isset($hub['site']['url']) ? (string)$hub['site']['url'] : home_url('/');

  // TLS from Hub (authoritative)
  $tls        = isset($hub['security']['tls']) ? $hub['security']['tls'] : array();
  $tls_valid  = (bool) ( isset($tls['valid']) ? $tls['valid'] : ( isset($hub['security']['tls_valid']) ? $hub['security']['tls_valid'] : false ) );
  $tls_issuer = isset($tls['issuer']) ? (string)$tls['issuer'] : '';
  $tls_expires= isset($tls['expires_at']) ? (string)$tls['expires_at'] : ( isset($tls['not_after']) ? (string)$tls['not_after'] : '' );
  $tls_checked= isset($tls['checked_at']) ? (string)$tls['checked_at'] : '';

  // Host/Infra from Hub
  $host  = '';
  if (isset($hub['infra']['host'])) $host = (string)$hub['infra']['host'];
  elseif (isset($hub['hosting']['provider'])) $host = (string)$hub['hosting']['provider'];

  // WordPress version from Hub then local
  $wpv   = isset($hub['wordpress']['version']) ? (string)$hub['wordpress']['version'] : ( isset($local['wordpress']['version']) ? (string)$local['wordpress']['version'] : '' );
  // Theme: prefer Hub if provided as object with name; else local
  $theme = (isset($hub['wordpress']['theme']) && is_array($hub['wordpress']['theme']) && isset($hub['wordpress']['theme']['name']))
    ? (string)$hub['wordpress']['theme']['name']
    : ( isset($local['wordpress']['theme']['name']) ? (string)$local['wordpress']['theme']['name'] : '' );

  // Content counts (Hub first) + fallback to local snapshots
  $pages = 0; $posts = 0;
  if (isset($hub['content']['pages_total'])) $pages = (int)$hub['content']['pages_total'];
  elseif (isset($hub['content']['pages']))   $pages = (int)$hub['content']['pages'];
  if (isset($hub['content']['posts_total'])) $posts = (int)$hub['content']['posts_total'];
  elseif (isset($hub['content']['posts']))   $posts = (int)$hub['content']['posts'];

  $pages_items = luna_extract_hub_items($hub, 'pages');
  if (!is_array($pages_items)) {
    $pages_items = luna_collect_local_post_type_snapshot('page');
  }
  if ($pages === 0 && is_array($pages_items)) {
    $pages = count($pages_items);
  }

  $posts_items = luna_extract_hub_items($hub, 'posts');
  if (!is_array($posts_items)) {
    $posts_items = luna_collect_local_post_type_snapshot('post');
  }
  if ($posts === 0 && is_array($posts_items)) {
    $posts = count($posts_items);
  }

  // Users
  $users_total = isset($hub['users']['total']) ? (int)$hub['users']['total'] : 0;
  if ($users_total === 0 && isset($hub['users']) && is_array($hub['users'])) {
    $users_total = count($hub['users']);
  }
  if ($users_total === 0) {
    $user_counts = count_users();
    if (isset($user_counts['total_users'])) {
      $users_total = (int) $user_counts['total_users'];
    }
  }

  $users_items = luna_extract_hub_items($hub, 'users');
  if (!is_array($users_items)) {
    $users_items = array();
  }

  $plugins_items = array();
  if (isset($hub['plugins']) && is_array($hub['plugins'])) {
    $plugins_items = $hub['plugins'];
  } elseif (isset($local['plugins']) && is_array($local['plugins'])) {
    $plugins_items = $local['plugins'];
  }

  $themes_items = array();
  if (isset($hub['themes']) && is_array($hub['themes'])) {
    $themes_items = $hub['themes'];
  } elseif (isset($local['themes']) && is_array($local['themes'])) {
    $themes_items = $local['themes'];
  }

  // Updates (Hub first; fallback to derived counts)
  $plugin_updates = isset($hub['updates']['plugins_pending']) ? (int)$hub['updates']['plugins_pending'] : 0;
  $theme_updates  = isset($hub['updates']['themes_pending'])  ? (int)$hub['updates']['themes_pending']  : 0;
  if ($plugin_updates === 0 && !empty($plugins_items)) {
    $c = 0; foreach ($plugins_items as $p) { if (!empty($p['update_available'])) $c++; } $plugin_updates = $c;
  }
  if ($theme_updates === 0 && !empty($themes_items)) {
    $c = 0; foreach ($themes_items as $t) { if (!empty($t['update_available'])) $c++; } $theme_updates = $c;
  }
  $core_updates = 0;
  if (isset($hub['updates']['core_pending'])) {
    $core_updates = (int) $hub['updates']['core_pending'];
  } elseif (!empty($local['wordpress']['core_update_available'])) {
    $core_updates = $local['wordpress']['core_update_available'] ? 1 : 0;
  }

  $facts = array(
    'site_url'   => $site_url,
    'tls'        => array(
      'valid'    => (bool)$tls_valid,
      'issuer'   => $tls_issuer,
      'expires'  => $tls_expires,
      'checked'  => $tls_checked,
    ),
    'host'       => $host,
    'wp_version' => $wpv,
    'theme'      => $theme,
    'counts'     => array(
      'pages'   => $pages,
      'posts'   => $posts,
      'users'   => $users_total,
      'plugins' => is_array($plugins_items) ? count($plugins_items) : 0,
    ),
    'updates'    => array(
      'plugins' => $plugin_updates,
      'themes'  => $theme_updates,
      'core'    => $core_updates,
    ),
    'generated'  => gmdate('c'),
    'comprehensive' => false,
  );

  if ($license) {
    $ga4_info = luna_fetch_ga4_metrics_from_hub($license);
    if ($ga4_info && isset($ga4_info['metrics'])) {
      $facts['ga4_metrics'] = $ga4_info['metrics'];
      if (!empty($ga4_info['last_synced'])) {
        $facts['ga4_last_synced'] = $ga4_info['last_synced'];
      }
      if (!empty($ga4_info['date_range'])) {
        $facts['ga4_date_range'] = $ga4_info['date_range'];
      }
      if (!empty($ga4_info['source_url'])) {
        $facts['ga4_source_url'] = $ga4_info['source_url'];
      }
      if (!empty($ga4_info['property_id'])) {
        $facts['ga4_property_id'] = $ga4_info['property_id'];
      }
      if (!empty($ga4_info['measurement_id'])) {
        $facts['ga4_measurement_id'] = $ga4_info['measurement_id'];
      }
    }
  }

  $facts['__source'] = 'basic';

  return $facts;
}

/* Enhanced facts with comprehensive Hub data */
function luna_get_active_theme_status($comprehensive) {
  // First try to get from themes array (more accurate)
  if (isset($comprehensive['themes']) && is_array($comprehensive['themes'])) {
    foreach ($comprehensive['themes'] as $theme) {
      if (isset($theme['is_active']) && $theme['is_active']) {
        return true;
      }
    }
  }
  
  // Fallback to basic theme info
  return isset($comprehensive['wordpress']['theme']['is_active']) ? (bool)$comprehensive['wordpress']['theme']['is_active'] : true;
}

function luna_profile_facts_comprehensive() {
  $license = luna_get_license();
  if (!$license) {
    error_log('[Luna] No license key found, falling back to basic facts');
    $fallback = luna_profile_facts(); // fallback to basic facts
    $fallback['__source'] = 'fallback-basic';
    return $fallback;
  }
  
  // Try to fetch comprehensive data from VL Hub profile
  $hub_url = luna_widget_hub_base();
  $endpoint = $hub_url . '/wp-json/vl-hub/v1/profile';
  
  error_log('[Luna] Fetching comprehensive data from: ' . $endpoint);
  error_log('[Luna] Using license: ' . substr($license, 0, 8) . '...');
  
  $response = wp_remote_get($endpoint . '?license=' . urlencode($license), array(
    'headers' => array('X-Luna-License' => $license),
    'timeout' => 10
  ));
  
  if (is_wp_error($response)) {
    error_log('[Luna] Error fetching comprehensive data: ' . $response->get_error_message());
    $fallback = luna_profile_facts();
    $fallback['__source'] = 'fallback-basic';
    return $fallback; // fallback
  }
  
  $code = wp_remote_retrieve_response_code($response);
  error_log('[Luna] Response code: ' . $code);
  
  if ($code < 200 || $code >= 300) {
    error_log('[Luna] HTTP error, falling back to basic facts');
    $fallback = luna_profile_facts();
    $fallback['__source'] = 'fallback-basic';
    return $fallback; // fallback
  }
  
  $comprehensive = json_decode(wp_remote_retrieve_body($response), true);
  if (is_array($comprehensive)) {
    $comprehensive = luna_hub_normalize_payload($comprehensive);
  }

  if (!is_array($comprehensive)) {
    error_log('[Luna] Invalid JSON response, falling back to basic facts');
    $fallback = luna_profile_facts();
    $fallback['__source'] = 'fallback-basic';
    return $fallback; // fallback
  }

  $hub_collections = luna_hub_collect_collections(false, array('profile' => $comprehensive));

  error_log('[Luna] Successfully fetched comprehensive data: ' . print_r($comprehensive, true));

  // Build enhanced facts from comprehensive data with local fallbacks
  $local_snapshot = luna_snapshot_system();

  $site_url = isset($comprehensive['home_url']) ? (string) $comprehensive['home_url'] : (isset($local_snapshot['site']['home_url']) ? (string) $local_snapshot['site']['home_url'] : home_url('/'));
  $https    = isset($comprehensive['https']) ? (bool) $comprehensive['https'] : (isset($local_snapshot['site']['https']) ? (bool) $local_snapshot['site']['https'] : is_ssl());
  $wp_version = isset($comprehensive['wordpress']['version']) ? (string) $comprehensive['wordpress']['version'] : (isset($local_snapshot['wordpress']['version']) ? (string) $local_snapshot['wordpress']['version'] : '');

  $theme_data = array();
  if (isset($comprehensive['wordpress']['theme']) && is_array($comprehensive['wordpress']['theme'])) {
    $theme_data = $comprehensive['wordpress']['theme'];
  } elseif (isset($local_snapshot['wordpress']['theme']) && is_array($local_snapshot['wordpress']['theme'])) {
    $theme_data = $local_snapshot['wordpress']['theme'];
  }
  $theme_name    = isset($theme_data['name']) ? (string) $theme_data['name'] : '';
  $theme_version = isset($theme_data['version']) ? (string) $theme_data['version'] : '';
  $theme_active  = isset($theme_data['is_active']) ? (bool) $theme_data['is_active'] : luna_get_active_theme_status($comprehensive);

  $tls_data = array();
  if (isset($comprehensive['security']['tls']) && is_array($comprehensive['security']['tls'])) {
    $tls_data = $comprehensive['security']['tls'];
  } elseif (isset($comprehensive['tls']) && is_array($comprehensive['tls'])) {
    $tls_data = $comprehensive['tls'];
  }
  $tls_valid   = isset($tls_data['valid']) ? (bool) $tls_data['valid'] : false;
  $tls_issuer  = isset($tls_data['issuer']) ? (string) $tls_data['issuer'] : '';
  $tls_expires = '';
  if (isset($tls_data['expires'])) {
    $tls_expires = (string) $tls_data['expires'];
  } elseif (isset($tls_data['expires_at'])) {
    $tls_expires = (string) $tls_data['expires_at'];
  } elseif (isset($tls_data['not_after'])) {
    $tls_expires = (string) $tls_data['not_after'];
  }
  $tls_checked = isset($tls_data['checked_at']) ? (string) $tls_data['checked_at'] : '';

  $host = isset($comprehensive['host']) ? (string) $comprehensive['host'] : '';
  if ($host === '' && isset($comprehensive['hosting']['provider'])) {
    $host = (string) $comprehensive['hosting']['provider'];
  }

  $plugins_items = luna_extract_hub_items($comprehensive, 'plugins');
  if (!is_array($plugins_items)) {
    $plugins_items = isset($local_snapshot['plugins']) ? $local_snapshot['plugins'] : array();
  }

  $themes_items = luna_extract_hub_items($comprehensive, 'themes');
  if (!is_array($themes_items)) {
    $themes_items = isset($local_snapshot['themes']) ? $local_snapshot['themes'] : array();
  }

  $pages_items = luna_extract_hub_items($comprehensive, 'pages');
  if (!is_array($pages_items)) {
    $pages_items = luna_collect_local_post_type_snapshot('page');
  }

  $posts_items = luna_extract_hub_items($comprehensive, 'posts');
  if (!is_array($posts_items)) {
    $posts_items = luna_collect_local_post_type_snapshot('post');
  }

  $users_items = luna_extract_hub_items($comprehensive, 'users');
  if (!is_array($users_items) && isset($comprehensive['users']) && is_array($comprehensive['users'])) {
    $users_items = $comprehensive['users'];
  }
  if (!is_array($users_items)) {
    $users_items = array();
  }

  $pages_count = is_array($pages_items) ? count($pages_items) : 0;
  if ($pages_count === 0 && isset($comprehensive['counts']['pages'])) {
    $pages_count = (int) $comprehensive['counts']['pages'];
  } elseif ($pages_count === 0 && isset($comprehensive['content']['pages_total'])) {
    $pages_count = (int) $comprehensive['content']['pages_total'];
  }

  $posts_count = is_array($posts_items) ? count($posts_items) : 0;
  if ($posts_count === 0 && isset($comprehensive['counts']['posts'])) {
    $posts_count = (int) $comprehensive['counts']['posts'];
  } elseif ($posts_count === 0 && isset($comprehensive['content']['posts_total'])) {
    $posts_count = (int) $comprehensive['content']['posts_total'];
  }

  $users_count = is_array($users_items) ? count($users_items) : 0;
  if ($users_count === 0 && isset($comprehensive['users_total'])) {
    $users_count = (int) $comprehensive['users_total'];
  } elseif ($users_count === 0 && isset($comprehensive['users']) && is_array($comprehensive['users'])) {
    $users_count = count($comprehensive['users']);
  }

  $plugins_count = is_array($plugins_items) ? count($plugins_items) : 0;

  $plugin_updates = 0;
  if (is_array($plugins_items)) {
    foreach ($plugins_items as $plugin) {
      if (!empty($plugin['update_available'])) {
        $plugin_updates++;
      }
    }
  }

  $theme_updates = 0;
  if (is_array($themes_items)) {
    foreach ($themes_items as $theme_row) {
      if (!empty($theme_row['update_available'])) {
        $theme_updates++;
      }
    }
  }

  $core_updates = 0;
  if (isset($comprehensive['wordpress']['core_update_available'])) {
    $core_updates = $comprehensive['wordpress']['core_update_available'] ? 1 : 0;
  } elseif (!empty($local_snapshot['wordpress']['core_update_available'])) {
    $core_updates = $local_snapshot['wordpress']['core_update_available'] ? 1 : 0;
  }

  $facts = array(
    'site_url'   => $site_url,
    'https'      => $https,
    'wp_version' => $wp_version,
    'theme'      => $theme_name,
    'theme_version' => $theme_version,
    'theme_active'  => $theme_active,
    'tls'        => array(
      'valid'   => $tls_valid,
      'issuer'  => $tls_issuer,
      'expires' => $tls_expires,
      'checked' => $tls_checked,
    ),
    'host'       => $host,
    'counts'     => array(
      'pages'   => $pages_count,
      'posts'   => $posts_count,
      'users'   => $users_count,
      'plugins' => $plugins_count,
    ),
    'updates'    => array(
      'plugins' => $plugin_updates,
      'themes'  => $theme_updates,
      'core'    => $core_updates,
    ),
    'generated'  => gmdate('c'),
    'comprehensive' => true, // Flag to indicate this is comprehensive data
    'plugins' => isset($comprehensive['plugins']) ? $comprehensive['plugins'] : array(),
    'users' => isset($comprehensive['users']) ? $comprehensive['users'] : array(),
    'themes' => isset($comprehensive['themes']) ? $comprehensive['themes'] : array(),
    'posts' => isset($comprehensive['_posts']['items']) ? $comprehensive['_posts']['items'] : array(),
    'pages' => isset($comprehensive['_pages']['items']) ? $comprehensive['_pages']['items'] : array(),
    'security' => isset($comprehensive['security']) ? $comprehensive['security'] : array(), // Add security data
  );
  
  $ga4_info = null;
  if (isset($comprehensive['ga4_metrics']) && is_array($comprehensive['ga4_metrics'])) {
    $ga4_info = array(
      'metrics'        => $comprehensive['ga4_metrics'],
      'last_synced'    => isset($comprehensive['ga4_last_synced']) ? $comprehensive['ga4_last_synced'] : (isset($comprehensive['last_synced']) ? $comprehensive['last_synced'] : null),
      'date_range'     => isset($comprehensive['ga4_date_range']) ? $comprehensive['ga4_date_range'] : null,
      'source_url'     => isset($comprehensive['ga4_source_url']) ? $comprehensive['ga4_source_url'] : (isset($comprehensive['source_url']) ? $comprehensive['source_url'] : null),
      'property_id'    => isset($comprehensive['ga4_property_id']) ? $comprehensive['ga4_property_id'] : null,
      'measurement_id' => isset($comprehensive['ga4_measurement_id']) ? $comprehensive['ga4_measurement_id'] : null,
    );
    error_log('[Luna] GA4 metrics present in comprehensive payload.');
  } else {
    error_log('[Luna] No GA4 metrics in comprehensive payload, attempting data streams fetch.');
    $ga4_info = luna_fetch_ga4_metrics_from_hub($license);
  }

  if ($ga4_info && isset($ga4_info['metrics'])) {
    $facts['ga4_metrics'] = $ga4_info['metrics'];
    if (!empty($ga4_info['last_synced'])) {
      $facts['ga4_last_synced'] = $ga4_info['last_synced'];
    }
    $facts['updates']['plugins'] = $plugin_updates;
  }
  
  $ga4_info = null;
  if (isset($comprehensive['ga4_metrics']) && is_array($comprehensive['ga4_metrics'])) {
    $ga4_info = array(
      'metrics'        => $comprehensive['ga4_metrics'],
      'last_synced'    => isset($comprehensive['ga4_last_synced']) ? $comprehensive['ga4_last_synced'] : (isset($comprehensive['last_synced']) ? $comprehensive['last_synced'] : null),
      'date_range'     => isset($comprehensive['ga4_date_range']) ? $comprehensive['ga4_date_range'] : null,
      'source_url'     => isset($comprehensive['ga4_source_url']) ? $comprehensive['ga4_source_url'] : (isset($comprehensive['source_url']) ? $comprehensive['source_url'] : null),
      'property_id'    => isset($comprehensive['ga4_property_id']) ? $comprehensive['ga4_property_id'] : null,
      'measurement_id' => isset($comprehensive['ga4_measurement_id']) ? $comprehensive['ga4_measurement_id'] : null,
    );
    error_log('[Luna] GA4 metrics present in comprehensive payload.');
  } else {
    error_log('[Luna] No GA4 metrics in comprehensive payload, attempting data streams fetch.');
    $ga4_info = luna_fetch_ga4_metrics_from_hub($license);
  }

  if ($ga4_info && isset($ga4_info['metrics'])) {
    $facts['ga4_metrics'] = $ga4_info['metrics'];
    if (!empty($ga4_info['last_synced'])) {
      $facts['ga4_last_synced'] = $ga4_info['last_synced'];
    }
    if (!empty($ga4_info['date_range'])) {
      $facts['ga4_date_range'] = $ga4_info['date_range'];
    }
    if (!empty($ga4_info['source_url'])) {
      $facts['ga4_source_url'] = $ga4_info['source_url'];
    }
    if (!empty($ga4_info['property_id'])) {
      $facts['ga4_property_id'] = $ga4_info['property_id'];
    }
    if (!empty($ga4_info['measurement_id'])) {
      $facts['ga4_measurement_id'] = $ga4_info['measurement_id'];
    }
    error_log('[Luna] GA4 metrics hydrated: ' . print_r($facts['ga4_metrics'], true));
  } else {
    error_log('[Luna] Unable to hydrate GA4 metrics from Hub.');
  }

  if (!empty($hub_collections)) {
    $facts['hub_collections'] = $hub_collections;

    $collection_map = array(
      'profile'      => 'hub_profile',
      'connections'  => 'hub_connections',
      'cloudops'     => 'hub_cloudops',
      'content'      => 'hub_content',
      'search'       => 'hub_search',
      'analytics'    => 'hub_analytics',
      'marketing'    => 'hub_marketing',
      'ecommerce'    => 'hub_ecommerce',
      'security'     => 'hub_security',
      'web_infra'    => 'hub_web_infra',
      'identity'     => 'hub_identity',
      'competitive'  => 'hub_competitive',
      'data_streams' => 'hub_data_streams',
      'users'        => 'hub_users',
      'plugins'      => 'hub_plugins',
      'themes'       => 'hub_themes',
      'updates'      => 'hub_updates',
    );

    foreach ($collection_map as $source_key => $dest_key) {
      if (isset($hub_collections[$source_key])) {
        $facts[$dest_key] = $hub_collections[$source_key];
      }
    }

    $facts['hub_sources_loaded'] = isset($hub_collections['_meta']['categories'])
      ? $hub_collections['_meta']['categories']
      : array_keys(array_diff_key($hub_collections, array('_meta' => true)));
  }

  // Fetch competitor analysis data - first try from comprehensive profile
  $competitor_urls = array();
  error_log('[Luna Widget] Checking comprehensive profile for competitors: ' . print_r(isset($comprehensive['competitors']) ? $comprehensive['competitors'] : 'NOT SET', true));
  
  if (isset($comprehensive['competitors']) && is_array($comprehensive['competitors']) && !empty($comprehensive['competitors'])) {
    // Extract competitor URLs from enriched profile
    foreach ($comprehensive['competitors'] as $competitor) {
      if (!empty($competitor['url'])) {
        $competitor_urls[] = $competitor['url'];
      } elseif (!empty($competitor['domain'])) {
        $competitor_urls[] = 'https://' . $competitor['domain'];
      }
    }
    $facts['competitors'] = $competitor_urls;
    error_log('[Luna Widget] Found competitors in comprehensive profile: ' . print_r($competitor_urls, true));
  } else {
    error_log('[Luna Widget] No competitors in comprehensive profile, falling back to direct fetch');
    // Fallback: fetch competitor data directly
    $competitor_data = luna_fetch_competitor_data($license);
    if ($competitor_data) {
      $facts['competitors'] = $competitor_data['competitors'] ?? array();
      $facts['competitor_reports'] = $competitor_data['reports'] ?? array();
      $competitor_urls = $facts['competitors'];
      error_log('[Luna Widget] Fetched competitors via direct call: ' . print_r($competitor_urls, true));
    } else {
      error_log('[Luna Widget] No competitor data found via direct fetch');
    }
  }
  
  // Fetch competitor reports if not already in comprehensive data
  if (empty($facts['competitor_reports']) && !empty($competitor_urls)) {
    $competitor_data = luna_fetch_competitor_data($license);
    if ($competitor_data && !empty($competitor_data['reports'])) {
      $facts['competitor_reports'] = $competitor_data['reports'];
    }
  }
  
  // Fetch VLDR data for each competitor and client domain
  if (!empty($competitor_urls) || !empty($site_url)) {
    $vldr_data = array();
    
    // Fetch VLDR for all competitors
    foreach ($competitor_urls as $competitor_url) {
      $domain = parse_url($competitor_url, PHP_URL_HOST);
      if ($domain) {
        $vldr = luna_fetch_vldr_data($domain, $license);
        if ($vldr) {
          $vldr_data[$domain] = $vldr;
        }
      }
    }
    
    // Also fetch VLDR for client's own domain
    $client_domain = parse_url($site_url, PHP_URL_HOST);
    if ($client_domain) {
      $client_vldr = luna_fetch_vldr_data($client_domain, $license);
      if ($client_vldr) {
        $vldr_data[$client_domain] = $client_vldr;
        $vldr_data[$client_domain]['is_client'] = true;
      }
    }
    
    if (!empty($vldr_data)) {
      $facts['vldr'] = $vldr_data;
    }
  }
  
  // Add performance metrics if available
  if (isset($comprehensive['performance']) && is_array($comprehensive['performance'])) {
    $facts['performance'] = $comprehensive['performance'];
  }
  
  // Add SEO data if available
  if (isset($comprehensive['seo']) && is_array($comprehensive['seo'])) {
    $facts['seo'] = $comprehensive['seo'];
  }
  
  // Add data stream summary if available
  if (isset($comprehensive['data_streams_summary']) && is_array($comprehensive['data_streams_summary'])) {
    $facts['data_streams_summary'] = $comprehensive['data_streams_summary'];
  }

  error_log('[Luna] Built comprehensive facts: ' . print_r(array_keys($facts), true));

  $facts['__source'] = 'comprehensive';

  return $facts;
}

/* Local snapshot used ONLY as fallback when Hub fact missing */
function luna_snapshot_system() {
  global $wp_version; $theme = wp_get_theme();
  if (!function_exists('get_plugins')) { @require_once ABSPATH . 'wp-admin/includes/plugin.php'; }
  $plugins = function_exists('get_plugins') ? (array)get_plugins() : array();
  $active  = (array) get_option('active_plugins', array());
  $up_pl   = get_site_transient('update_plugins');

  $plugins_out = array();
  foreach ($plugins as $slug => $info) {
    $update_available = isset($up_pl->response[$slug]);
    $plugins_out[] = array(
      'slug' => $slug,
      'name' => isset($info['Name']) ? $info['Name'] : $slug,
      'version' => isset($info['Version']) ? $info['Version'] : null,
      'active' => in_array($slug, $active, true),
      'update_available' => (bool)$update_available,
      'new_version' => $update_available ? (isset($up_pl->response[$slug]->new_version) ? $up_pl->response[$slug]->new_version : null) : null,
    );
  }
  $themes = wp_get_themes(); $up_th = get_site_transient('update_themes');
  $themes_out = array();
  foreach ($themes as $stylesheet => $th) {
    $update_available = isset($up_th->response[$stylesheet]);
    $themes_out[] = array(
      'stylesheet' => $stylesheet,
      'name' => $th->get('Name'),
      'version' => $th->get('Version'),
      'is_active' => (wp_get_theme()->get_stylesheet() === $stylesheet),
      'update_available' => (bool)$update_available,
      'new_version' => $update_available ? (isset($up_th->response[$stylesheet]['new_version']) ? $up_th->response[$stylesheet]['new_version'] : null) : null,
    );
  }

  // Check for WordPress core updates
  $core_updates = get_site_transient('update_core');
  $core_update_available = false;
  if (isset($core_updates->updates) && is_array($core_updates->updates)) {
    foreach ($core_updates->updates as $update) {
      if ($update->response === 'upgrade') {
        $core_update_available = true;
        break;
      }
    }
  }

  return array(
    'site' => array('home_url' => home_url('/'), 'https' => (wp_parse_url(home_url('/'), PHP_URL_SCHEME) === 'https')),
    'wordpress' => array(
      'version' => isset($wp_version) ? $wp_version : null,
      'core_update_available' => $core_update_available,
      'theme'   => array(
        'name'       => $theme->get('Name'),
        'version'    => $theme->get('Version'),
        'stylesheet' => $theme->get_stylesheet(),
        'template'   => $theme->get_template(),
      ),
    ),
    'plugins'     => $plugins_out,
    'themes'      => $themes_out,
    'generated_at'=> gmdate('c'),
  );
}

/* ============================================================
 * FRONT-END: Widget/Shortcode + JS (with history hydrate)
 * ============================================================ */
add_action('wp_enqueue_scripts', function () {
  wp_register_script(
    'luna-composer',
    LUNA_WIDGET_ASSET_URL . 'assets/js/luna-composer.js',
    array(),
    LUNA_WIDGET_PLUGIN_VERSION,
    true
  );
});

add_shortcode('luna_chat', function(){
  if (get_option(LUNA_WIDGET_OPT_MODE, 'widget') !== 'shortcode') {
    return '<!-- [luna_chat] disabled: floating widget active -->';
  }
  ob_start(); ?>
  <div class="luna-wrap">
    <div class="luna-thread"></div>
    <form class="luna-form" onsubmit="return false;">
      <input class="luna-input" autocomplete="off" placeholder="Ask Luna…" />
      <button class="luna-send" type="submit">Send</button>
    </form>
  </div>
  <?php return ob_get_clean();
});

add_shortcode('luna_composer', function($atts = array(), $content = '') {
  $enabled = get_option(LUNA_WIDGET_OPT_COMPOSER_ENABLED, '1') === '1';
  if (!$enabled) {
    return '<div class="luna-composer-disabled">' . esc_html__('Luna Composer is currently disabled.', 'luna') . '</div>';
  }

  wp_enqueue_script('luna-composer');

  static $composer_localized = false;
  if (!$composer_localized) {
    $prompts = array();
    foreach (luna_composer_default_prompts() as $prompt) {
      $label  = isset($prompt['label']) ? (string) $prompt['label'] : '';
      $prompt_text = isset($prompt['prompt']) ? (string) $prompt['prompt'] : '';
      if ($label === '' || $prompt_text === '') {
        continue;
      }
      $prompts[] = array(
        'label'  => sanitize_text_field($label),
        'prompt' => wp_strip_all_tags($prompt_text),
      );
    }

    wp_localize_script('luna-composer', 'lunaComposerSettings', array(
      'restUrlChat' => esc_url_raw(rest_url('luna_widget/v1/chat')),
      'nonce'       => is_user_logged_in() ? wp_create_nonce('wp_rest') : null,
      'integrated'  => true,
      'prompts'     => $prompts,
    ));
    $composer_localized = true;
  }

  $id = esc_attr(wp_unique_id('luna-composer-'));
  $placeholder = apply_filters('luna_composer_placeholder', __('Describe what you need from Luna…', 'luna'));
  $inner_content = trim($content) !== '' ? do_shortcode($content) : '';

  ob_start();
  ?>
  <div class="luna-composer" data-luna-composer data-luna-composer-id="<?php echo $id; ?>">
    <div class="luna-composer__card">
      <div data-luna-prompts>
        <?php echo $inner_content ? wp_kses_post($inner_content) : ''; ?>
      </div>
      <form class="luna-composer__form" action="#" method="post" novalidate>
        <div
          class="luna-composer__editor is-empty"
          data-luna-composer-editor
          contenteditable="true"
          role="textbox"
          aria-multiline="true"
          spellcheck="true"
          data-placeholder="<?php echo esc_attr($placeholder); ?>"
        ></div>
        <div class="luna-composer__actions">
          <button type="submit" class="luna-composer__submit" data-luna-composer-submit>
            <?php esc_html_e('', 'luna'); ?>
          </button>
        </div>
      </form>
      <div class="luna-composer__response" data-luna-composer-response></div>
    </div>
  </div>
  <?php
  return ob_get_clean();
});

add_action('wp_footer', function () {
  if (is_admin()) return;

  $mode = get_option(LUNA_WIDGET_OPT_MODE, 'widget');
  $ui   = get_option(LUNA_WIDGET_OPT_SETTINGS, array());
  $pos  = isset($ui['position']) ? $ui['position'] : 'bottom-right';

  if ($mode === 'widget') {
    $pos_css = 'bottom:20px;right:20px;';
    if ($pos === 'top-left') { $pos_css = 'top:20px;left:20px;'; }
    elseif ($pos === 'top-center') { $pos_css = 'top:20px;left:50%;transform:translateX(-50%);'; }
    elseif ($pos === 'top-right') { $pos_css = 'top:20px;right:20px;'; }
    elseif ($pos === 'bottom-left') { $pos_css = 'bottom:20px;left:20px;'; }
    elseif ($pos === 'bottom-center') { $pos_css = 'bottom:20px;left:50%;transform:translateX(-50%);'; }

    $title = esc_html(isset($ui['title']) ? $ui['title'] : 'Luna Chat');
    $avatar= esc_url(isset($ui['avatar_url']) ? $ui['avatar_url'] : '');
    $hdr   = esc_html(isset($ui['header_text']) ? $ui['header_text'] : "Hi, I'm Luna");
    $sub   = esc_html(isset($ui['sub_text']) ? $ui['sub_text'] : 'How can I help today?');

    $panel_anchor = (strpos($pos,'bottom') !== false ? 'bottom:80px;' : 'top:80px;')
                  . (strpos($pos,'right') !== false ? 'right:20px;' : (strpos($pos,'left') !== false ? 'left:20px;' : 'left:50%;transform:translateX(-50%);'));
    ?>
    <style>
      .luna-fab { position:fixed; z-index:999999; <?php echo $pos_css; ?> }
      .luna-launcher{display:flex;align-items:center;gap:10px;background:#111;color:#fff;border:1px solid #5A5753;border-radius:999px;padding:8px 12px 8px 8px;cursor:pointer;box-shadow:0 8px 24px rgba(0,0,0,.25)}
      .luna-launcher .ava{width:36px;height:36px;border-radius:50%;background:#222;overflow:hidden;display:inline-flex;align-items:center;justify-content:center}
      .luna-launcher .txt{line-height:1.2;display:flex;flex-direction:column}
      .luna-panel{position:fixed; z-index:99991; <?php echo $panel_anchor; ?> width:clamp(320px,92vw,420px);max-height:min(70vh,560px);display:none;flex-direction:column;border-radius:12px;border:1px solid #5A5753;background:#000;color:#fff;overflow:hidden;box-shadow:0 24px 48px rgba(0,0,0,.4)}
      .luna-panel.show{display:flex}
      .luna-head{padding:10px 12px;font-weight:600;background:#0b0b0b;border-bottom:1px solid #333;display:flex;align-items:center;justify-content:space-between}
      .luna-thread{padding:10px 12px;overflow:auto;flex:1 1 auto}
      .luna-form{display:flex;gap:8px;padding:10px 12px;border-top:1px solid #333}
      .luna-input{flex:1 1 auto;background:#111;color:#fff;border:1px solid #333;border-radius:10px;padding:8px 10px}
      .luna-send{background:#111;color:#fff;border:1px solid #5A5753;border-radius:10px;padding:8px 12px;cursor:pointer}
      .luna-thread .luna-msg{clear:both;margin:6px 0}
      .luna-thread .luna-user{float:right;background:#fff4e9;color:#000;display:inline-block;padding:8px 10px;border-radius:10px;max-width:85%;word-wrap:break-word}
      .luna-thread .luna-assistant{float:left;background:#111;border:1px solid #333;color:#fff;display:inline-block;padding:8px 10px;border-radius:10px;max-width:85%;word-wrap:break-word}
      .luna-thread .luna-session-closure{opacity:.85;font-style:italic}
      .luna-session-ended{position:fixed;z-index:99992;width:clamp(320px,92vw,420px);display:none;align-items:center;justify-content:center}
      .luna-session-ended.show{display:flex}
      .luna-session-ended-card{background:#000;border:1px solid #5A5753;border-radius:12px;padding:24px 20px;display:flex;flex-direction:column;gap:12px;align-items:center;text-align:center;box-shadow:0 24px 48px rgba(0,0,0,.4);width:100%}
      .luna-session-ended-card h2{margin:0;font-size:1.25rem}
      .luna-session-ended-card p{margin:0;color:#ccc}
      .luna-session-ended-card .luna-session-restart{background:#2c74ff;color:#fff;border:0;border-radius:8px;padding:10px 18px;font-weight:600;cursor:pointer}
      .luna-session-ended-card .luna-session-restart:hover{background:#4c8bff}
      .luna-session-ended-inline{margin-top:12px;background:#000;border:1px solid #5A5753;border-radius:12px;padding:24px 20px;text-align:center;display:flex;flex-direction:column;gap:12px;align-items:center}
      .luna-session-ended-inline button{background:#2c74ff;color:#fff;border:0;border-radius:8px;padding:10px 18px;font-weight:600;cursor:pointer}
      .luna-session-ended-inline button:hover{background:#4c8bff}
    </style>
    <div class="luna-fab" aria-live="polite">
      <button class="luna-launcher" aria-expanded="false" aria-controls="luna-panel" title="<?php echo $title; ?>">
        <span class="ava">
          <?php if ($avatar): ?><img src="<?php echo $avatar; ?>" alt="" style="width:36px;height:36px;object-fit:cover"><?php else: ?>
            <svg width="24" height="24" viewBox="0 0 36 36" fill="none" aria-hidden="true"><circle cx="18" cy="18" r="18" fill="#222"/><path d="M18 18a6 6 0 100-12 6 6 0 000 12zm0 2c-6 0-10 3.2-10 6v2h20v-2c0-2.8-4-6-10-6z" fill="#666"/></svg>
          <?php endif; ?>
        </span>
        <span class="txt"><strong><?php echo $hdr; ?></strong><span><?php echo $sub; ?></span></span>
      </button>
      <div id="luna-panel" class="luna-panel" role="dialog" aria-label="<?php echo $title; ?>">
        <div class="luna-head"><span><?php echo $title; ?></span><button class="luna-close" style="background:transparent;border:0;color:#fff;cursor:pointer" aria-label="Close">✕</button></div>
        <div class="luna-thread"></div>
        <form class="luna-form"><input class="luna-input" placeholder="Ask Luna…" autocomplete="off"><button type="button" class="luna-send">Send</button></form>
      </div>
    </div>
    <div id="luna-session-ended" class="luna-session-ended" style="<?php echo $panel_anchor; ?> display:none;" role="dialog" aria-modal="true" aria-labelledby="luna-session-ended-title">
      <div class="luna-session-ended-card">
        <h2 id="luna-session-ended-title">Your session has ended</h2>
        <p>Start another one now.</p>
        <button type="button" class="luna-session-restart">Start New Session</button>
      </div>
    </div>
    <script>
      (function(){
        var fab=document.querySelector('.luna-launcher'), panel=document.querySelector('#luna-panel');
        var closeBtn=document.querySelector('.luna-close');
        var ended=document.querySelector('#luna-session-ended');

        async function hydrate(thread){
          if (!thread || thread.__hydrated) return;
          try{
            const res = await fetch('<?php echo esc_url_raw( rest_url('luna_widget/v1/chat/history') ); ?>');
            const data = await res.json();
            if (data && Array.isArray(data.items)) {
              data.items.forEach(function(turn){
                if (turn.user) { var u=document.createElement('div'); u.className='luna-msg luna-user'; u.textContent=turn.user; thread.appendChild(u); }
                if (turn.assistant) { var a=document.createElement('div'); a.className='luna-msg luna-assistant'; a.textContent=turn.assistant; thread.appendChild(a); }
              });
              thread.scrollTop = thread.scrollHeight;
            }
          }catch(e){ console.warn('[Luna] hydrate failed', e); }
          finally { thread.__hydrated = true; }
        }
        function showEnded(){
          if (ended) ended.classList.add('show');
          if (panel) panel.classList.remove('show');
          if (fab) fab.setAttribute('aria-expanded','false');
        }
        function hideEnded(){
          if (ended) ended.classList.remove('show');
        }
        window.__lunaShowSessionEnded = showEnded;
        window.__lunaHideSessionEnded = hideEnded;
        function toggle(open){
          if(!panel||!fab) return;
          var will=(typeof open==='boolean')?open:!panel.classList.contains('show');
          if (will && window.LunaChatSession && window.LunaChatSession.closing) {
            showEnded();
            return;
          }
          if (will && ended) ended.classList.remove('show');
          panel.classList.toggle('show',will);
          fab.setAttribute('aria-expanded',will?'true':'false');
          if (will) {
            hydrate(panel.querySelector('.luna-thread'));
            if (window.LunaChatSession && typeof window.LunaChatSession.onPanelToggle === 'function') {
              window.LunaChatSession.onPanelToggle(true);
            }
          } else {
            if (window.LunaChatSession && typeof window.LunaChatSession.onPanelToggle === 'function') {
              window.LunaChatSession.onPanelToggle(false);
            }
            hideEnded();
          }
        }
        if(fab) fab.addEventListener('click', function(){ toggle(); });
        if(closeBtn) closeBtn.addEventListener('click', function(){ toggle(false); });
        if(ended){
          var restartBtn = ended.querySelector('.luna-session-restart');
          if (restartBtn) restartBtn.addEventListener('click', function(){
            if (window.LunaChatSession && typeof window.LunaChatSession.restartSession === 'function') {
              window.LunaChatSession.restartSession();
            }
          });
        }
        document.addEventListener('keydown', function(e){
          if(e.key==='Escape'){
            toggle(false);
            hideEnded();
          }
        });
      })();
    </script>
    <?php
  }
  ?>
  <script>
    (function(){
      if (typeof window.chat_inactive_response !== 'function') {
        window.chat_inactive_response = function () {
          return "I haven't heard from you in a while, are you still there? If not, I'll close out this chat automatically in 3 minutes.";
        };
      }

      if (window.__lunaBoot) return;
      window.__lunaBoot = true;

      const defaultInactivityMessage = "I haven't heard from you in a while, are you still there? If not, I'll close out this chat automatically in 3 minutes.";
      const defaultSessionEndMessage = "This chat session has been closed due to inactivity.";

      const sessionState = {
        inactivityDelay: 120000,
        closureDelay: 180000,
        inactivityTimer: null,
        closureTimer: null,
        closing: false,
        restarting: false,
        _inlineEndedCard: null
      };

      const chatEndpoint = '<?php echo esc_url_raw( rest_url('luna_widget/v1/chat') ); ?>';
      const chatHistoryEndpoint = '<?php echo esc_url_raw( rest_url('luna_widget/v1/chat/history') ); ?>';
      const chatInactiveEndpoint = '<?php echo esc_url_raw( rest_url('luna_widget/v1/chat/inactive') ); ?>';
      const chatSessionEndEndpoint = '<?php echo esc_url_raw( rest_url('luna_widget/v1/chat/session/end') ); ?>';
      const chatSessionResetEndpoint = '<?php echo esc_url_raw( rest_url('luna_widget/v1/chat/session/reset') ); ?>';

      function resolveInactivityMessage() {
        try {
          if (typeof window.chat_inactive_response === 'function') {
            var custom = window.chat_inactive_response();
            if (custom && typeof custom === 'string') {
              return custom;
            }
          }
        } catch (err) {
          console.warn('[Luna] inactive response error', err);
        }
        return defaultInactivityMessage;
      }

      function resolveSessionEndMessage() {
        return defaultSessionEndMessage;
      }

      function getPrimaryThread() {
        return document.querySelector('#luna-panel .luna-thread') || document.querySelector('.luna-thread');
      }

      function appendAssistantMessage(thread, message, extraClass) {
        if (!thread || !message) return null;
        var el = document.createElement('div');
        el.className = 'luna-msg luna-assistant' + (extraClass ? ' ' + extraClass : '');
        el.textContent = message;
        thread.appendChild(el);
        thread.scrollTop = thread.scrollHeight;
        return el;
      }

      function cancelTimers() {
        if (sessionState.inactivityTimer) {
          clearTimeout(sessionState.inactivityTimer);
          sessionState.inactivityTimer = null;
        }
        if (sessionState.closureTimer) {
          clearTimeout(sessionState.closureTimer);
          sessionState.closureTimer = null;
        }
      }

      function setFormsDisabled(disabled) {
        document.querySelectorAll('.luna-form .luna-input').forEach(function(input){
          input.disabled = disabled;
          if (disabled) input.blur();
        });
        document.querySelectorAll('.luna-form .luna-send').forEach(function(button){
          button.disabled = disabled;
        });
      }

      function showSessionEndedUI() {
        if (typeof window.__lunaShowSessionEnded === 'function') {
          window.__lunaShowSessionEnded();
        } else {
          var wrap = document.querySelector('.luna-wrap');
          if (wrap) {
            wrap.querySelectorAll('.luna-thread, .luna-form').forEach(function(el){ el.style.display = 'none'; });
            if (!sessionState._inlineEndedCard) {
              var card = document.createElement('div');
              card.className = 'luna-session-ended-inline';
              card.innerHTML = '<h2>Your session has ended</h2><p>Start another one now.</p><button type="button" class="luna-session-restart">Start New Session</button>';
              wrap.appendChild(card);
              var btn = card.querySelector('.luna-session-restart');
              if (btn) {
                btn.addEventListener('click', function(){ restartSession(); });
              }
              sessionState._inlineEndedCard = card;
            }
          }
        }
      }

      function hideSessionEndedUI() {
        if (typeof window.__lunaHideSessionEnded === 'function') {
          window.__lunaHideSessionEnded();
        }
        if (sessionState._inlineEndedCard) {
          var card = sessionState._inlineEndedCard;
          sessionState._inlineEndedCard = null;
          if (card.parentNode) card.parentNode.removeChild(card);
        }
        document.querySelectorAll('.luna-wrap .luna-thread').forEach(function(el){ el.style.display = ''; });
        document.querySelectorAll('.luna-wrap .luna-form').forEach(function(el){ el.style.display = ''; });
      }

      function markActivity() {
        if (sessionState.closing) return;
        cancelTimers();
        var thread = getPrimaryThread();
        if (thread) {
          thread.__inactiveWarned = false;
        }
        sessionState.inactivityTimer = window.setTimeout(handleInactivityWarning, sessionState.inactivityDelay);
      }

      function handleInactivityWarning() {
        sessionState.inactivityTimer = null;
        if (sessionState.closing) return;
        var message = resolveInactivityMessage();
        var thread = getPrimaryThread();
        if (thread && !thread.__inactiveWarned) {
          thread.__inactiveWarned = true;
          appendAssistantMessage(thread, message);
        }
        try {
          fetch(chatInactiveEndpoint, {
            method: 'POST',
            headers: {'Content-Type':'application/json'},
            body: JSON.stringify({ message: message })
          }).catch(function(err){
            console.warn('[Luna] inactive log failed', err);
          });
        } catch (err) {
          console.warn('[Luna] inactive fetch error', err);
        }
        if (sessionState.closureTimer) clearTimeout(sessionState.closureTimer);
        sessionState.closureTimer = window.setTimeout(handleSessionClosure, sessionState.closureDelay);
      }

      function handleSessionClosure() {
        sessionState.closureTimer = null;
        if (sessionState.closing) return;
        sessionState.closing = true;
        cancelTimers();
        var message = resolveSessionEndMessage();
        var thread = getPrimaryThread();
        if (thread && !thread.__sessionClosed) {
          thread.__sessionClosed = true;
          appendAssistantMessage(thread, message, 'luna-session-closure');
        }
        setFormsDisabled(true);
        showSessionEndedUI();
        try {
          fetch(chatSessionEndEndpoint, {
            method: 'POST',
            headers: {'Content-Type':'application/json'},
            body: JSON.stringify({ reason: 'inactivity', message: message })
          }).catch(function(err){
            console.warn('[Luna] session end failed', err);
          });
        } catch (err) {
          console.warn('[Luna] session end error', err);
        }
      }

      function clearThreads() {
        document.querySelectorAll('.luna-thread').forEach(function(thread){
          thread.innerHTML = '';
          thread.__hydrated = false;
          thread.__inactiveWarned = false;
          thread.__sessionClosed = false;
        });
      }

      function restartSession() {
        if (sessionState.restarting) return;
        sessionState.restarting = true;
        cancelTimers();
        document.querySelectorAll('.luna-session-restart').forEach(function(btn){
          btn.disabled = true;
        });
        try {
          fetch(chatSessionResetEndpoint, {
            method: 'POST',
            headers: {'Content-Type':'application/json'},
            body: JSON.stringify({ reason: 'user_restart' })
          })
          .then(function(){
            sessionState.closing = false;
            setFormsDisabled(false);
            hideSessionEndedUI();
            clearThreads();
            if (typeof window.__lunaHydrateAny === 'function') {
              window.__lunaHydrateAny(true);
            } else {
              hydrateAny(true);
            }
            var panel = document.getElementById('luna-panel');
            if (panel) panel.classList.add('show');
            var fab = document.querySelector('.luna-launcher');
            if (fab) fab.setAttribute('aria-expanded','true');
            var input = document.querySelector('#luna-panel .luna-input') || document.querySelector('.luna-input');
            if (input) input.focus();
          })
          .catch(function(err){
            console.error('[Luna] session reset failed', err);
          })
          .finally(function(){
            sessionState.restarting = false;
            document.querySelectorAll('.luna-session-restart').forEach(function(btn){
              btn.disabled = false;
            });
          });
        } catch (err) {
          console.error('[Luna] session reset error', err);
          sessionState.restarting = false;
          document.querySelectorAll('.luna-session-restart').forEach(function(btn){
            btn.disabled = false;
          });
        }
      }

      function onPanelToggle(open) {
        if (open) {
          if (sessionState.closing) {
            showSessionEndedUI();
            return;
          }
          markActivity();
        }
      }

      async function hydrateAny(forceAll){
        document.querySelectorAll('.luna-thread').forEach(async function(thread){
          if (!forceAll && thread.closest('#luna-panel')) return;
          if (!thread.__hydrated) {
            try{
              const r = await fetch(chatHistoryEndpoint);
              const d = await r.json();
              if (d && Array.isArray(d.items)) {
                d.items.forEach(function(turn){
                  if (turn.user) { var u=document.createElement('div'); u.className='luna-msg luna-user'; u.textContent=turn.user; thread.appendChild(u); }
                  if (turn.assistant) { var a=document.createElement('div'); a.className='luna-msg luna-assistant'; a.textContent=turn.assistant; thread.appendChild(a); }
                });
                thread.scrollTop = thread.scrollHeight;
              }
            }catch(e){ console.warn('[Luna] hydrate failed', e); }
            finally { thread.__hydrated = true; }
          }
        });
      }

      function submitFrom(form){
        try{
          if (sessionState.closing) {
            showSessionEndedUI();
            return;
          }
          var input = form.querySelector('.luna-input'); if(!input) return;
          var text = (input.value||'').trim(); if(!text) return;

          markActivity();

          var thread = form.parentElement.querySelector('.luna-thread') || document.querySelector('.luna-thread');
          if (!thread) { thread = document.createElement('div'); thread.className='luna-thread'; form.parentElement.insertBefore(thread, form); }

          var btn = form.querySelector('.luna-send, button[type="submit"]');
          input.disabled=true; if(btn) btn.disabled=true;

          var u=document.createElement('div'); u.className='luna-msg luna-user'; u.textContent=text; thread.appendChild(u); thread.scrollTop=thread.scrollHeight;

          fetch(chatEndpoint, {
            method: 'POST',
            headers: {'Content-Type':'application/json'},
            body: JSON.stringify({ prompt: text })
          })
          .then(function(r){ return r.json().catch(function(){return {};}); })
          .then(function(d){
            var msg = (d && d.answer) ? d.answer : (d.error ? ('Error: '+d.error) : 'Sorry—no response.');
            appendAssistantMessage(thread, msg);
          })
          .catch(function(err){
            var e=document.createElement('div'); e.className='luna-msg luna-assistant'; e.textContent='Network error. Please try again.'; thread.appendChild(e);
            console.error('[Luna]', err);
          })
          .finally(function(){ input.value=''; input.disabled=false; if(btn) btn.disabled=false; input.focus(); markActivity(); });
        }catch(e){ console.error('[Luna unexpected]', e); }
      }

      function bind(form){
        if(!form || form.__bound) return; form.__bound = true;
        form.setAttribute('novalidate','novalidate');
        form.addEventListener('submit', function(e){ e.preventDefault(); e.stopPropagation(); e.stopImmediatePropagation(); submitFrom(form); }, true);
        var input=form.querySelector('.luna-input'), btn=form.querySelector('.luna-send');
        if (input) {
          input.addEventListener('keydown', function(e){
            if (sessionState.closing) { e.preventDefault(); showSessionEndedUI(); return; }
            if(e.key==='Enter' && !e.shiftKey && !e.isComposing){
              e.preventDefault(); e.stopPropagation(); e.stopImmediatePropagation(); submitFrom(form);
            }
            markActivity();
          }, true);
          input.addEventListener('focus', markActivity, true);
          input.addEventListener('input', markActivity, true);
        }
        if (btn) { try{btn.type='button';}catch(_){} btn.addEventListener('click', function(e){
          e.preventDefault(); e.stopPropagation(); e.stopImmediatePropagation(); submitFrom(form);
        }, true); }
        form.addEventListener('pointerdown', markActivity, true);
      }

      function scan(){ document.querySelectorAll('.luna-form').forEach(bind); }
      scan(); hydrateAny();
      window.__lunaHydrateAny = hydrateAny;
      sessionState.markActivity = markActivity;
      sessionState.cancelTimers = cancelTimers;
      sessionState.restartSession = restartSession;
      sessionState.showSessionEndedUI = showSessionEndedUI;
      sessionState.hideSessionEndedUI = hideSessionEndedUI;
      sessionState.onPanelToggle = onPanelToggle;
      window.LunaChatSession = sessionState;

      try{ new MutationObserver(function(){ if (scan.__t) cancelAnimationFrame(scan.__t); scan.__t=requestAnimationFrame(function(){ scan(); hydrateAny(); }); }).observe(document.documentElement,{childList:true,subtree:true}); }catch(_){}
      if (document.readyState==='loading') document.addEventListener('DOMContentLoaded', function(){ scan(); hydrateAny(); }, {once:true});
    })();
  </script>
  <?php
});

/* ============================================================
 * OPENAI HELPERS
 * ============================================================ */
function luna_get_openai_key() {
  if (defined('LUNA_OPENAI_API_KEY') && LUNA_OPENAI_API_KEY) return (string)LUNA_OPENAI_API_KEY;
  $k = get_option('luna_openai_api_key', '');
  return is_string($k) ? trim($k) : '';
}

function luna_openai_messages_with_facts($pid, $user_text, $facts) {
  $site_url = isset($facts['site_url']) ? (string)$facts['site_url'] : home_url('/');
  $https    = isset($facts['https']) ? ($facts['https'] ? 'yes' : 'no') : 'unknown';
  $tls      = isset($facts['tls']) && is_array($facts['tls']) ? $facts['tls'] : array();
  $host     = isset($facts['host']) && $facts['host'] !== '' ? (string)$facts['host'] : 'unknown';
  $wpv      = isset($facts['wp_version']) && $facts['wp_version'] !== '' ? (string)$facts['wp_version'] : 'unknown';
  $theme    = isset($facts['theme']) && $facts['theme'] !== '' ? (string)$facts['theme'] : 'unknown';
  $theme_version = isset($facts['theme_version']) && $facts['theme_version'] !== '' ? (string)$facts['theme_version'] : 'unknown';
  $theme_active  = isset($facts['theme_active']) ? ($facts['theme_active'] ? 'yes' : 'no') : 'unknown';
  $counts  = isset($facts['counts']) && is_array($facts['counts']) ? $facts['counts'] : array();
  $updates = isset($facts['updates']) && is_array($facts['updates']) ? $facts['updates'] : array();

  $count_pages  = isset($counts['pages']) ? (int)$counts['pages'] : 0;
  $count_posts  = isset($counts['posts']) ? (int)$counts['posts'] : 0;
  $count_users  = isset($counts['users']) ? (int)$counts['users'] : 0;
  $count_plugins= isset($counts['plugins']) ? (int)$counts['plugins'] : 0;

  $updates_plugins = isset($updates['plugins']) ? (int)$updates['plugins'] : 0;
  $updates_themes  = isset($updates['themes']) ? (int)$updates['themes'] : 0;
  $updates_core    = isset($updates['core']) ? (int)$updates['core'] : 0;

  $facts_text = "FACTS (from Visible Light Hub)\n"
    . "- Site URL: " . $site_url . "\n"
    . "- HTTPS: " . $https . "\n"
    . "- TLS valid: " . (isset($tls['valid']) ? ($tls['valid'] ? 'yes' : 'no') : 'unknown')
    . (!empty($tls['issuer']) ? " (issuer: " . $tls['issuer'] . ")" : '')
    . (!empty($tls['expires']) ? " (expires: " . $tls['expires'] . ")" : '') . "\n"
    . "- Host: " . $host . "\n"
    . "- WordPress: " . $wpv . "\n"
    . "- Theme: " . $theme . " (version: " . $theme_version . ")\n"
    . "- Theme active: " . $theme_active . "\n"
    . "- Counts: pages " . $count_pages . ", posts " . $count_posts . ", users " . $count_users . ", plugins " . $count_plugins . "\n"
    . "- Updates pending: plugins " . $updates_plugins . ", themes " . $updates_themes . ", WordPress Core " . $updates_core . "\n";
    
  // Add comprehensive data if available
  if (isset($facts['comprehensive']) && $facts['comprehensive']) {
    $facts_text .= "\nINSTALLED PLUGINS:\n";
    if (isset($facts['plugins']) && is_array($facts['plugins'])) {
      foreach ($facts['plugins'] as $plugin) {
        $status = !empty($plugin['active']) ? 'active' : 'inactive';
        $update = !empty($plugin['update_available']) ? ' (update available)' : '';
        $facts_text .= "- " . $plugin['name'] . " v" . $plugin['version'] . " (" . $status . ")" . $update . "\n";
      }
    }
    
    $facts_text .= "\nINSTALLED THEMES:\n";
    if (isset($facts['themes']) && is_array($facts['themes'])) {
      foreach ($facts['themes'] as $theme) {
        $status = !empty($theme['is_active']) ? 'active' : 'inactive';
        $update = !empty($theme['update_available']) ? ' (update available)' : '';
        $facts_text .= "- " . $theme['name'] . " v" . $theme['version'] . " (" . $status . ")" . $update . "\n";
      }
    }
    
    $facts_text .= "\nPUBLISHED POSTS:\n";
    if (isset($facts['posts']) && is_array($facts['posts'])) {
      foreach ($facts['posts'] as $post) {
        $facts_text .= "- " . $post['title'] . " (ID: " . $post['id'] . ")\n";
      }
    }
    
    $facts_text .= "\nPAGES:\n";
    if (isset($facts['pages']) && is_array($facts['pages'])) {
      foreach ($facts['pages'] as $page) {
        $status = isset($page['status']) ? $page['status'] : 'published';
        $facts_text .= "- " . $page['title'] . " (" . $status . ", ID: " . $page['id'] . ")\n";
      }
    }
    
    $facts_text .= "\nUSERS:\n";
    if (isset($facts['users']) && is_array($facts['users'])) {
      foreach ($facts['users'] as $user) {
        $facts_text .= "- " . $user['name'] . " (" . $user['username'] . ") - " . $user['email'] . "\n";
      }
    }
  }
  
  $facts_text .= "\nRULES: Prefer the FACTS for this client. If a fact is missing/uncertain, say you're unsure and suggest next steps. Keep answers concise and specific to this site when relevant.";

  // Get additional data from VL Hub
  $hub_data = luna_get_hub_data();
  if ($hub_data && isset($hub_data['summary'])) {
    $facts_text .= "\n\nHUB INSIGHTS:\n" . $hub_data['summary'];
    if (isset($hub_data['metrics'])) {
      $facts_text .= "\n\nHUB METRICS:\n";
      foreach ($hub_data['metrics'] as $key => $value) {
        $facts_text .= "- " . ucfirst(str_replace('_', ' ', $key)) . ": " . $value . "\n";
      }
    }
  }
  
  // Add competitor analysis data
  if (isset($facts['competitors']) && is_array($facts['competitors']) && !empty($facts['competitors'])) {
    $facts_text .= "\n\nCOMPETITOR ANALYSIS:\n";
    $facts_text .= "Tracked competitors: " . implode(', ', $facts['competitors']) . "\n";
    
    if (isset($facts['competitor_reports']) && is_array($facts['competitor_reports']) && !empty($facts['competitor_reports'])) {
      foreach ($facts['competitor_reports'] as $report_data) {
        $comp_url = $report_data['url'] ?? '';
        $comp_domain = $report_data['domain'] ?? parse_url($comp_url, PHP_URL_HOST);
        $report = $report_data['report'] ?? array();
        
        if ($comp_domain) {
          $facts_text .= "\nCompetitor: " . $comp_domain . "\n";
          if (!empty($report['lighthouse_score'])) {
            $facts_text .= "  - Lighthouse Score: " . $report['lighthouse_score'] . "\n";
          }
          if (!empty($report['meta_description'])) {
            $facts_text .= "  - Meta Description: " . substr($report['meta_description'], 0, 100) . "...\n";
          }
          if (!empty($report['keywords'])) {
            $top_keywords = array_slice($report['keywords'], 0, 5);
            $facts_text .= "  - Top Keywords: " . implode(', ', $top_keywords) . "\n";
          }
        }
      }
    }
  }
  
  // Add VLDR (Domain Ranking) data
  if (isset($facts['vldr']) && is_array($facts['vldr']) && !empty($facts['vldr'])) {
    $facts_text .= "\n\nDOMAIN RANKING (VL-DR) DATA:\n";
    foreach ($facts['vldr'] as $domain => $vldr_data) {
      $is_client = isset($vldr_data['is_client']) && $vldr_data['is_client'];
      $label = $is_client ? "Client Domain" : "Competitor";
      $facts_text .= $label . ": " . $domain . "\n";
      if (isset($vldr_data['vldr_score'])) {
        $facts_text .= "  - VL-DR Score: " . number_format($vldr_data['vldr_score'], 1) . " (0-100)\n";
      }
      if (isset($vldr_data['ref_domains'])) {
        $facts_text .= "  - Referring Domains: ~" . number_format($vldr_data['ref_domains'] / 1000, 1) . "k\n";
      }
      if (isset($vldr_data['indexed_pages'])) {
        $facts_text .= "  - Indexed Pages: ~" . number_format($vldr_data['indexed_pages'] / 1000, 1) . "k\n";
      }
      if (isset($vldr_data['lighthouse_avg'])) {
        $facts_text .= "  - Lighthouse Average: " . $vldr_data['lighthouse_avg'] . "\n";
      }
      if (isset($vldr_data['security_grade'])) {
        $facts_text .= "  - Security Grade: " . $vldr_data['security_grade'] . "\n";
      }
      if (isset($vldr_data['domain_age_years'])) {
        $facts_text .= "  - Domain Age: " . number_format($vldr_data['domain_age_years'], 1) . " years\n";
      }
      if (isset($vldr_data['uptime_percent'])) {
        $facts_text .= "  - Uptime: " . number_format($vldr_data['uptime_percent'], 2) . "%\n";
      }
      if (isset($vldr_data['metric_date'])) {
        $facts_text .= "  - Last Updated: " . $vldr_data['metric_date'] . "\n";
      }
      $facts_text .= "\n";
    }
    $facts_text .= "Note: VL-DR (Visible Light Domain Ranking) is computed from public indicators: Common Crawl/Index, Bing Web Search, SecurityHeaders.com, WHOIS, Visible Light Uptime monitoring, and Lighthouse performance scores.\n";
  }
  
  // Add performance metrics
  if (isset($facts['performance']) && is_array($facts['performance'])) {
    $facts_text .= "\n\nPERFORMANCE METRICS:\n";
    if (isset($facts['performance']['lighthouse']) && is_array($facts['performance']['lighthouse'])) {
      $lh = $facts['performance']['lighthouse'];
      $facts_text .= "Lighthouse Scores:\n";
      $facts_text .= "  - Performance: " . ($lh['performance'] ?? 'N/A') . "\n";
      $facts_text .= "  - Accessibility: " . ($lh['accessibility'] ?? 'N/A') . "\n";
      $facts_text .= "  - SEO: " . ($lh['seo'] ?? 'N/A') . "\n";
      $facts_text .= "  - Best Practices: " . ($lh['best_practices'] ?? 'N/A') . "\n";
      if (!empty($lh['last_updated'])) {
        $facts_text .= "  - Last Updated: " . $lh['last_updated'] . "\n";
      }
    }
  }
  
  // Add SEO data
  if (isset($facts['seo']) && is_array($facts['seo'])) {
    $facts_text .= "\n\nSEO METRICS:\n";
    $seo = $facts['seo'];
    $facts_text .= "  - Total Clicks: " . ($seo['total_clicks'] ?? 0) . "\n";
    $facts_text .= "  - Total Impressions: " . ($seo['total_impressions'] ?? 0) . "\n";
    $facts_text .= "  - Average CTR: " . number_format(($seo['avg_ctr'] ?? 0) * 100, 2) . "%\n";
    $facts_text .= "  - Average Position: " . number_format($seo['avg_position'] ?? 0, 1) . "\n";
    if (!empty($seo['top_queries']) && is_array($seo['top_queries'])) {
      $facts_text .= "  - Top Search Queries:\n";
      foreach (array_slice($seo['top_queries'], 0, 5) as $query) {
        $facts_text .= "    * " . ($query['query'] ?? '') . " - " . ($query['clicks'] ?? 0) . " clicks, " . number_format(($query['ctr'] ?? 0), 2) . "% CTR\n";
      }
    }
  }
  
  // Add data stream summary
  if (isset($facts['data_streams_summary']) && is_array($facts['data_streams_summary'])) {
    $streams_summary = $facts['data_streams_summary'];
    $facts_text .= "\n\nDATA STREAMS:\n";
    $facts_text .= "  - Total Streams: " . ($streams_summary['total'] ?? 0) . "\n";
    $facts_text .= "  - Active Streams: " . ($streams_summary['active'] ?? 0) . "\n";
    if (!empty($streams_summary['by_category']) && is_array($streams_summary['by_category'])) {
      $facts_text .= "  - Streams by Category:\n";
      foreach ($streams_summary['by_category'] as $category => $count) {
        $facts_text .= "    * " . ucfirst($category) . ": " . $count . "\n";
      }
    }
    if (!empty($streams_summary['recent']) && is_array($streams_summary['recent'])) {
      $facts_text .= "  - Recent Streams:\n";
      foreach ($streams_summary['recent'] as $stream) {
        $facts_text .= "    * " . ($stream['name'] ?? '') . " (" . ($stream['category'] ?? '') . ") - " . ($stream['last_updated'] ?? '') . "\n";
      }
    }
  }

  $messages = array(
    array('role'=>'system','content'=>"You are Luna, a concise, friendly assistant for the site's owners."),
    array('role'=>'system','content'=>$facts_text),
  );
  $t = get_post_meta($pid, 'transcript', true);
  if (!is_array($t)) $t = array();
  $slice = array_slice($t, max(0, count($t)-8));
  foreach ($slice as $row) {
    $u = trim(isset($row['user']) ? (string)$row['user'] : '');
    $a = trim(isset($row['assistant']) ? (string)$row['assistant'] : '');
    if ($u !== '') $messages[] = array('role'=>'user','content'=>$u);
    if ($a !== '') $messages[] = array('role'=>'assistant','content'=>$a);
  }
  if ($user_text !== '') $messages[] = array('role'=>'user','content'=>$user_text);
  return $messages;
}

function luna_generate_openai_answer($pid, $prompt, $facts) {
  $api_key = luna_get_openai_key();
  if ($api_key === '') {
    return null;
  }

  $model    = apply_filters('luna_openai_model', 'gpt-4o-mini');
  $messages = luna_openai_messages_with_facts($pid, $prompt, $facts);
  $payload  = array(
    'model'       => $model,
    'messages'    => $messages,
    'temperature' => 0.2,
    'max_tokens'  => 500,
  );

  $response = wp_remote_post('https://api.openai.com/v1/chat/completions', array(
    'timeout' => 30,
    'headers' => array(
      'Content-Type'  => 'application/json',
      'Authorization' => 'Bearer ' . $api_key,
    ),
    'body'    => wp_json_encode($payload),
  ));

  if (is_wp_error($response)) {
    error_log('[Luna Widget] OpenAI request failed: ' . $response->get_error_message());
    return null;
  }

  $status   = (int) wp_remote_retrieve_response_code($response);
  $raw_body = wp_remote_retrieve_body($response);
  if ($status >= 400) {
    error_log('[Luna Widget] OpenAI HTTP ' . $status . ': ' . substr($raw_body, 0, 500));
    return null;
  }

  $decoded = json_decode($raw_body, true);
  if (!is_array($decoded)) {
    error_log('[Luna Widget] OpenAI returned invalid JSON.');
    return null;
  }

  $content = '';
  if (!empty($decoded['choices'][0]['message']['content'])) {
    $content = (string) $decoded['choices'][0]['message']['content'];
  } elseif (!empty($decoded['choices'][0]['text'])) {
    $content = (string) $decoded['choices'][0]['text'];
  }

  $content = trim($content);
  if ($content === '') {
    return null;
  }

  $result = array(
    'answer' => $content,
    'model'  => $model,
  );

  if (!empty($decoded['usage']) && is_array($decoded['usage'])) {
    $result['usage'] = $decoded['usage'];
  }

  return $result;
}

/* ============================================================
 * REST: Chat + History + Hub-facing lists + Utilities
 * ============================================================ */

function luna_widget_chat_handler( WP_REST_Request $req ) {
  $prompt = trim( (string) $req->get_param('prompt') );
  if ($prompt === '') {
    return new WP_REST_Response(array('answer'=>'Please enter a message.'), 200);
  }

  $context = $req->get_param('context');
  $context = is_string($context) ? sanitize_key($context) : '';
  $is_composer = ($context === 'composer');
  $composer_enabled = get_option(LUNA_WIDGET_OPT_COMPOSER_ENABLED, '1') === '1';
  if ($is_composer && !$composer_enabled) {
    return new WP_REST_Response(array(
      'answer' => __('Luna Composer is currently disabled by an administrator.', 'luna'),
      'meta'   => array('source' => 'system', 'composer' => false),
    ), 200);
  }

  $pid   = luna_conv_id();
  $facts = luna_profile_facts_comprehensive(); // Use comprehensive Hub data
  $site_url = isset($facts['site_url']) ? (string)$facts['site_url'] : home_url('/');
  $security = isset($facts['security']) && is_array($facts['security']) ? $facts['security'] : array();
  $lc    = function_exists('mb_strtolower') ? mb_strtolower($prompt) : strtolower($prompt);
  $answer = '';
  $meta   = array('source' => 'deterministic');
  if ($is_composer) {
    $meta['composer'] = true;
  }

  // Deterministic intents using comprehensive Hub data
  if (preg_match('/\b(tls|ssl|https|certificate|cert)\b/', $lc)) {
    $tls = isset($facts['tls']) && is_array($facts['tls']) ? $facts['tls'] : array();
    $security_tls = isset($security['tls']) && is_array($security['tls']) ? $security['tls'] : array();
    $tls_valid = isset($tls['valid']) ? $tls['valid'] : false;
    $tls_status = isset($security_tls['status']) ? $security_tls['status'] : '';
    $tls_version = isset($security_tls['version']) ? $security_tls['version'] : '';
    $tls_issuer = isset($security_tls['issuer']) ? $security_tls['issuer'] : (isset($tls['issuer']) ? $tls['issuer'] : '');
    $tls_provider = isset($security_tls['provider_guess']) ? $security_tls['provider_guess'] : '';
    $tls_valid_from = isset($security_tls['valid_from']) ? $security_tls['valid_from'] : '';
    $tls_valid_to = isset($security_tls['valid_to']) ? $security_tls['valid_to'] : (isset($tls['expires']) ? $tls['expires'] : '');
    $tls_host = isset($security_tls['host']) ? $security_tls['host'] : '';

    if ($tls_valid) {
      $details = array();
      if ($tls_status) $details[] = "Status: ".$tls_status;
      if ($tls_version) $details[] = "Version: ".$tls_version;
      if ($tls_issuer) $details[] = "Issuer: ".$tls_issuer;
      if ($tls_provider) $details[] = "Provider: ".$tls_provider;
      if ($tls_valid_from) $details[] = "Valid from: ".$tls_valid_from;
      if ($tls_valid_to) $details[] = "Valid to: ".$tls_valid_to;
      if ($tls_host) $details[] = "Host: ".$tls_host;

      $answer = "Yes—TLS/SSL is active for ".$site_url." (".implode(', ', $details).").";
    } else {
      $answer = "Hub shows TLS/SSL is not confirmed active for ".$site_url.". Please review the Security tab in Visible Light.";
    }
  }
  elseif (preg_match('/\bwordpress\b.*\bversion\b|\bwp\b.*\bversion\b/', $lc)) {
    $v = isset($facts['wp_version']) ? trim((string)$facts['wp_version']) : '';
    $answer = $v ? ("Your WordPress version is ".$v.".") : "I don't see a confirmed WordPress version in the Hub profile.";
  }
  elseif (preg_match('/\btheme\b.*\bactive\b|\bis.*theme.*active\b/', $lc)) {
    $theme_active = isset($facts['theme_active']) ? (bool)$facts['theme_active'] : true;
    $theme_name = isset($facts['theme']) ? (string)$facts['theme'] : '';
    if ($theme_name) {
      $answer = $theme_active ? ("Yes, the ".$theme_name." theme is currently active.") : ("No, the ".$theme_name." theme is not active.");
    } else {
      $answer = "I don't have confirmation on whether the current theme is active.";
    }
  }
  elseif (preg_match('/\bwhat.*theme|\btheme.*name|\bcurrent.*theme\b/', $lc)) {
    $theme_name = isset($facts['theme']) ? (string)$facts['theme'] : '';
    $answer = $theme_name ? ("You are using the ".$theme_name." theme.") : "I don't see a confirmed theme in the Hub profile.";
  }
  elseif (preg_match('/\bhello\b|\bhi\b|\bhey\b/', $lc)) {
    $answer = "Hello! I'm Luna, your friendly WebOps assistant. I have access to all your site data from Visible Light Hub. I can help you with WordPress version, themes, plugins, SSL status, and more. What would you like to know?";
  }
  elseif (preg_match('/\bup.*to.*date|\boutdated|\bupdate.*available\b/', $lc)) {
    $updates = isset($facts['updates']) && is_array($facts['updates']) ? $facts['updates'] : array();
    $core_updates = isset($updates['core']) ? (int)$updates['core'] : 0;
    $plugin_updates = isset($updates['plugins']) ? (int)$updates['plugins'] : 0;
    $theme_updates = isset($updates['themes']) ? (int)$updates['themes'] : 0;

    if ($core_updates > 0 || $plugin_updates > 0 || $theme_updates > 0) {
      $answer = "You have updates available: WordPress Core: ".$core_updates.", Plugins: ".$plugin_updates.", Themes: ".$theme_updates.". I recommend updating for security and performance.";
    } else {
      $answer = "Your WordPress installation appears to be up to date. No core, plugin, or theme updates are currently available.";
    }
  }
  elseif (preg_match('/\bthreat.*protection|\bsecurity.*scan|\bmalware.*protection|\bthreat.*detection\b/', $lc)) {
    $security_ids = isset($security['ids']) && is_array($security['ids']) ? $security['ids'] : array();
    $ids_provider = isset($security_ids['provider']) ? $security_ids['provider'] : '';
    $last_scan = isset($security_ids['last_scan']) ? $security_ids['last_scan'] : '';
    $last_result = isset($security_ids['result']) ? $security_ids['result'] : '';
    $scan_schedule = isset($security_ids['schedule']) ? $security_ids['schedule'] : '';

    if ($ids_provider) {
      $details = array();
      $details[] = "Provider: ".$ids_provider;
      if ($last_scan) $details[] = "Last scan: ".$last_scan;
      if ($last_result) $details[] = "Last result: ".$last_result;
      if ($scan_schedule) $details[] = "Schedule: ".$scan_schedule;

      $answer = "Yes, you have threat protection set up (".implode(', ', $details)."). This helps protect against malware and security threats.";
    } else {
      $answer = "I don't see specific threat protection details in your security profile. You may want to consider adding a security plugin like Wordfence or Sucuri for malware protection.";
    }
  }
  elseif (preg_match('/\bfirewall\b/', $lc)) {
    $security_waf = isset($security['waf']) && is_array($security['waf']) ? $security['waf'] : array();
    $waf_provider = isset($security_waf['provider']) ? $security_waf['provider'] : '';
    $last_audit = isset($security_waf['last_audit']) ? $security_waf['last_audit'] : '';
    if ($waf_provider) {
      $answer = "Yes, you have a firewall configured. Your WAF provider is ".$waf_provider." with the last audit on ".$last_audit.". This helps block malicious traffic before it reaches your site.";
    } else {
      $answer = "I don't see a specific firewall configuration in your security profile. Consider adding a Web Application Firewall (WAF) for additional protection.";
    }
  }
  elseif (preg_match('/\bcdn\b/', $lc)) {
    $answer = "I don't see specific CDN configuration details in your current profile. A CDN can improve your site's performance by serving content from locations closer to your visitors. Popular options include Cloudflare, MaxCDN, or KeyCDN.";
  }
  elseif (preg_match('/\bauthentication|\bmfa|\bpassword.*policy|\bsession.*timeout|\bsso\b/', $lc)) {
    $security_auth = isset($security['auth']) && is_array($security['auth']) ? $security['auth'] : array();
    $mfa = isset($security_auth['mfa']) ? $security_auth['mfa'] : '';
    $password_policy = isset($security_auth['password_policy']) ? $security_auth['password_policy'] : '';
    $session_timeout = isset($security_auth['session_timeout']) ? $security_auth['session_timeout'] : '';
    $sso_providers = isset($security_auth['sso_providers']) ? $security_auth['sso_providers'] : '';

    $details = array();
    if ($mfa) $details[] = "MFA: ".$mfa;
    if ($password_policy) $details[] = "Password Policy: ".$password_policy;
    if ($session_timeout) $details[] = "Session Timeout: ".$session_timeout;
    if ($sso_providers) $details[] = "SSO Providers: ".$sso_providers;

    if (!empty($details)) {
      $answer = "Your authentication settings (".implode(', ', $details).").";
    } else {
      $answer = "I don't see specific authentication details in your security profile. Consider setting up MFA, strong password policies, and appropriate session timeouts for better security.";
    }
  }
  elseif (preg_match('/\bdomain.*registrar|\bwho.*registered|\bdomain.*registered.*with\b/', $lc)) {
    $security_domain = isset($security['domain']) && is_array($security['domain']) ? $security['domain'] : array();
    $domain_name = isset($security_domain['domain']) ? $security_domain['domain'] : '';
    $registrar = isset($security_domain['registrar']) ? $security_domain['registrar'] : '';
    $registered_on = isset($security_domain['registered_on']) ? $security_domain['registered_on'] : '';
    $renewal_date = isset($security_domain['renewal_date']) ? $security_domain['renewal_date'] : '';
    $auto_renew = isset($security_domain['auto_renew']) ? $security_domain['auto_renew'] : '';
    $dns_records = isset($security_domain['dns_records']) ? $security_domain['dns_records'] : '';

    if ($registrar) {
      $details = array();
      if ($domain_name) $details[] = "Domain: ".$domain_name;
      $details[] = "Registrar: ".$registrar;
      if ($registered_on) $details[] = "Registered: ".$registered_on;
      if ($renewal_date) $details[] = "Renewal: ".$renewal_date;
      if ($auto_renew) $details[] = "Auto-renew: ".$auto_renew;
      if ($dns_records) $details[] = "DNS Records: ".$dns_records;

      $answer = "Your domain information (".implode(', ', $details).").";
    } else {
      $answer = "I don't have the domain registrar information in your current profile. You can check this in your domain management panel.";
    }
  }
  elseif (preg_match('/\bblog.*title|\bcreate.*title|\bwrite.*title|\bcontent.*idea\b/', $lc)) {
    $site_name = isset($facts['site_url']) ? parse_url($facts['site_url'], PHP_URL_HOST) : 'your website';
    $theme_name = isset($facts['theme']) ? $facts['theme'] : 'your theme';
    $answer = "Here are some blog title ideas for your new website: 'Welcome to ".$site_name." - A Fresh Digital Experience', 'Introducing Our New ".$theme_name."-Powered Website', 'Behind the Scenes: Building ".$site_name."', or 'What's New at ".$site_name." - A Complete Redesign'. Would you like me to suggest more specific topics?";
  }
  elseif (preg_match('/\bwhat.*can.*you.*do|\bwhat.*do.*you.*do|\bhelp.*with\b/', $lc)) {
    $answer = "I can help you with information about your WordPress site, including themes, plugins, SSL status, pages, posts, users, security settings, domain information, analytics data (page views, users, sessions, bounce rate, engagement), and more. All data comes from your Visible Light Hub profile. What would you like to know?";
  }
  elseif (preg_match('/\b(web.*intelligence.*report|intelligence.*report|comprehensive.*report|full.*report|detailed.*report|complete.*analysis)\b/', $lc)) {
    $answer = luna_generate_web_intelligence_report($facts);
  }
  elseif (preg_match('/\b(page.*views|pageviews|analytics|traffic|visitors|users|sessions|bounce.*rate|engagement)\b/', $lc)) {
    $answer = luna_handle_analytics_request($prompt, $facts);
  }
  elseif (preg_match('/\bcloudflare\b/', $lc)) {
    $answer = "Cloudflare is a popular CDN (Content Delivery Network) and security service that can improve your website's performance and protect it from threats. I don't see Cloudflare specifically configured in your current setup, but it's a great option to consider for faster loading times and enhanced security.";
  }
  elseif (preg_match('/\bdns.*records|\bdns\b/', $lc)) {
    $security_domain = isset($security['domain']) && is_array($security['domain']) ? $security['domain'] : array();
    $dns_records = isset($security_domain['dns_records']) ? $security_domain['dns_records'] : '';
    if ($dns_records) {
      $answer = "Here are your DNS records: ".$dns_records.". These control how your domain points to your hosting server and other services.";
    } else {
      $answer = "I don't have your DNS records in the current profile. You can check these in your domain registrar's control panel or hosting provider's DNS management section.";
    }
  }
  elseif (preg_match('/\blogin.*authenticator|\bauthenticator\b/', $lc)) {
    $security_auth = isset($security['auth']) && is_array($security['auth']) ? $security['auth'] : array();
    $mfa = isset($security_auth['mfa']) ? $security_auth['mfa'] : '';
    if ($mfa) {
      $answer = "Your login authentication is handled by ".$mfa.". This provides an extra layer of security beyond just passwords.";
    } else {
      $answer = "I don't see a specific authenticator configured in your security profile. Consider setting up two-factor authentication (2FA) for enhanced security.";
    }
  }
  elseif (preg_match('/\bquestion\b/', $lc)) {
    $answer = "Of course! I'm here to help. What would you like to know about your website?";
  }
  elseif (preg_match('/\bno\b/', $lc)) {
    $answer = "No problem! Is there anything else I can help you with regarding your website?";
  }
  elseif (preg_match('/\b(thank\s?you|thanks|great|awesome|excellent|perfect)\b/', $lc)) {
    $answer = "Glad I could help! Feel free to ask if you have any other questions about your site.";
  }
  elseif (preg_match('/\b(help|support|issue|problem|error|bug|broken|not working|trouble|stuck|confused|need assistance)\b/', $lc)) {
    $answer = luna_analyze_help_request($prompt, $facts);
  }
  elseif (preg_match('/\b(support email|send email|email support)\b/', $lc)) {
    $answer = luna_handle_help_option('support_email', $prompt, $facts);
  }
  elseif (preg_match('/\b(notify vl|notify visible light|alert vl|alert visible light)\b/', $lc)) {
    $answer = luna_handle_help_option('notify_vl', $prompt, $facts);
  }
  elseif (preg_match('/\b(report bug|bug report|report as bug)\b/', $lc)) {
    $answer = luna_handle_help_option('report_bug', $prompt, $facts);
  }
  elseif (preg_match('/\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/', $prompt)) {
    // Email address detected - send support email
    $email = luna_extract_email($prompt);
    if ($email) {
      $success = luna_send_support_email($email, $prompt, $facts);
      if ($success) {
        $answer = "✅ Perfect! I've sent a detailed snapshot of our conversation and your site data to " . $email . ". You should receive it shortly. Is there anything else I can help you with?";
      } else {
        $answer = "I encountered an issue sending the email. Let me try notifying the Visible Light team instead - would you like me to do that?";
      }
    } else {
      $answer = "I couldn't find a valid email address in your message. Could you please provide the email address where you'd like me to send the support snapshot?";
    }
  }
  elseif (preg_match("/\bhow.*many.*inactive.*themes|\binactive.*themes\b/", $lc)) {
    $inactive_themes = array();
    if (isset($facts["themes"]) && is_array($facts["themes"])) {
      foreach ($facts["themes"] as $theme) {
        if (empty($theme["is_active"])) {
          $inactive_themes[] = $theme["name"] . " v" . $theme["version"];
        }
      }
    }
    if (!empty($inactive_themes)) {
      $answer = "You have " . count($inactive_themes) . " inactive themes: " . implode(", ", $inactive_themes) . ".";
    } else {
      $answer = "You have no inactive themes. All installed themes are currently active.";
    }
  }
  elseif (preg_match("/\bhow.*many.*plugins|\bplugin.*count\b/", $lc)) {
    $plugin_count = isset($facts["counts"]["plugins"]) ? (int)$facts["counts"]["plugins"] : 0;
    $answer = "You currently have " . $plugin_count . " plugins installed.";
  }
  elseif (preg_match("/\bwhat.*plugins|\blist.*plugins\b/", $lc)) {
    if (isset($facts["plugins"]) && is_array($facts["plugins"]) && !empty($facts["plugins"])) {
      $plugin_list = array();
      foreach ($facts["plugins"] as $plugin) {
        $status = !empty($plugin["active"]) ? "active" : "inactive";
        $plugin_list[] = $plugin["name"] . " v" . $plugin["version"] . " (" . $status . ")";
      }
      $answer = "Your installed plugins are: " . implode(", ", $plugin_list) . ".";
    } else {
      $answer = "I don't see any plugins installed on your site.";
    }
  }
  elseif (preg_match('/\b(competitor|competitors|competitor.*analysis|competitor.*report|domain.*ranking|vldr|vl.*dr|dr.*score)\b/', $lc)) {
    // Competitor analysis and domain ranking queries
    error_log('[Luna Widget] Competitor query detected: ' . $prompt);
    error_log('[Luna Widget] Checking facts for competitors: ' . print_r(isset($facts['competitors']) ? $facts['competitors'] : 'NOT SET', true));
    error_log('[Luna Widget] Full facts keys: ' . print_r(array_keys($facts), true));
    
    if (isset($facts['competitors']) && is_array($facts['competitors']) && !empty($facts['competitors'])) {
      $competitor_list = array();
      foreach ($facts['competitors'] as $competitor_url) {
        $domain = parse_url($competitor_url, PHP_URL_HOST);
        if ($domain) {
          $competitor_list[] = $domain;
        }
      }
      
      if (!empty($competitor_list)) {
        $answer = "I have competitor analysis data for the following domains: " . implode(", ", $competitor_list) . ".\n\n";
        
        // Add VLDR data if available
        if (isset($facts['vldr']) && is_array($facts['vldr']) && !empty($facts['vldr'])) {
          $answer .= "**Domain Ranking (VL-DR) Scores:**\n";
          foreach ($facts['vldr'] as $domain => $vldr_data) {
            $is_client = isset($vldr_data['is_client']) && $vldr_data['is_client'];
            $label = $is_client ? "Your Domain" : "Competitor";
            $answer .= "\n" . $label . ": **" . $domain . "**\n";
            if (isset($vldr_data['vldr_score'])) {
              $score = (float) $vldr_data['vldr_score'];
              $color = $score >= 80 ? "excellent" : ($score >= 60 ? "good" : ($score >= 40 ? "fair" : "needs improvement"));
              $answer .= "  - VL-DR Score: **" . number_format($score, 1) . "/100** (" . $color . ")\n";
            }
            if (isset($vldr_data['ref_domains'])) {
              $answer .= "  - Referring Domains: ~" . number_format($vldr_data['ref_domains'] / 1000, 1) . "k\n";
            }
            if (isset($vldr_data['indexed_pages'])) {
              $answer .= "  - Indexed Pages: ~" . number_format($vldr_data['indexed_pages'] / 1000, 1) . "k\n";
            }
            if (isset($vldr_data['lighthouse_avg'])) {
              $answer .= "  - Lighthouse Average: " . $vldr_data['lighthouse_avg'] . "\n";
            }
            if (isset($vldr_data['security_grade'])) {
              $answer .= "  - Security Grade: **" . $vldr_data['security_grade'] . "**\n";
            }
            if (isset($vldr_data['domain_age_years'])) {
              $answer .= "  - Domain Age: " . number_format($vldr_data['domain_age_years'], 1) . " years\n";
            }
            if (isset($vldr_data['uptime_percent'])) {
              $answer .= "  - Uptime: " . number_format($vldr_data['uptime_percent'], 2) . "%\n";
            }
            if (isset($vldr_data['metric_date'])) {
              $answer .= "  - Last Updated: " . date('M j, Y', strtotime($vldr_data['metric_date'])) . "\n";
            }
          }
          $answer .= "\n*VL-DR is computed from public indicators: Common Crawl/Index, Bing Web Search, SecurityHeaders.com, WHOIS, Visible Light Uptime monitoring, and Lighthouse performance scores.*\n";
        }
        
        // Add competitor reports if available
        if (isset($facts['competitor_reports']) && is_array($facts['competitor_reports']) && !empty($facts['competitor_reports'])) {
          $answer .= "\n**Competitor Analysis Reports:**\n";
          foreach ($facts['competitor_reports'] as $report_data) {
            $comp_url = $report_data['url'] ?? '';
            $comp_domain = $report_data['domain'] ?? parse_url($comp_url, PHP_URL_HOST);
            $report = $report_data['report'] ?? array();
            
            if ($comp_domain && !empty($report)) {
              $answer .= "\n**" . $comp_domain . ":**\n";
              if (!empty($report['lighthouse_score'])) {
                $answer .= "  - Lighthouse Score: " . $report['lighthouse_score'] . "\n";
              }
              if (!empty($report['title'])) {
                $answer .= "  - Page Title: " . $report['title'] . "\n";
              }
              if (!empty($report['meta_description'])) {
                $answer .= "  - Meta Description: " . substr($report['meta_description'], 0, 150) . "...\n";
              }
              if (!empty($report['keywords']) && is_array($report['keywords'])) {
                $top_keywords = array_slice($report['keywords'], 0, 5);
                $answer .= "  - Top Keywords: " . implode(", ", $top_keywords) . "\n";
              }
              if (!empty($report['keyphrases']) && is_array($report['keyphrases'])) {
                $top_keyphrases = array_slice($report['keyphrases'], 0, 5);
                $answer .= "  - Top Keyphrases: " . implode(", ", $top_keyphrases) . "\n";
              }
            }
          }
        }
      } else {
        $answer = "I don't see any competitor analysis data configured. You can set up competitor analysis in your Visible Light Hub profile to track competitor domains and their performance metrics.";
      }
    } else {
      $answer = "I don't see any competitor analysis data configured. You can set up competitor analysis in your Visible Light Hub profile to track competitor domains and their performance metrics.";
    }
  }
  elseif (preg_match('/\b(domain.*rank|vldr|vl.*dr|dr.*score|ranking.*score)\b/', $lc) && preg_match('/\b(astronomer|siteassembly|nvidia|competitor|competitors)\b/i', $prompt)) {
    // Specific domain ranking query
    $domain_match = null;
    if (preg_match('/\b(astronomer\.io|siteassembly\.com|nvidia\.com)\b/i', $prompt, $matches)) {
      $domain_match = strtolower($matches[1]);
    } elseif (preg_match('/\b(astronomer|siteassembly|nvidia)\b/i', $prompt, $matches)) {
      $domain_lookup = array(
        'astronomer' => 'astronomer.io',
        'siteassembly' => 'siteassembly.com',
        'nvidia' => 'nvidia.com',
      );
      $key = strtolower($matches[1]);
      if (isset($domain_lookup[$key])) {
        $domain_match = $domain_lookup[$key];
      }
    }
    
    if ($domain_match && isset($facts['vldr'][$domain_match])) {
      $vldr_data = $facts['vldr'][$domain_match];
      $answer = "**Domain Ranking for " . $domain_match . ":**\n\n";
      if (isset($vldr_data['vldr_score'])) {
        $score = (float) $vldr_data['vldr_score'];
        $color = $score >= 80 ? "excellent" : ($score >= 60 ? "good" : ($score >= 40 ? "fair" : "needs improvement"));
        $answer .= "**VL-DR Score: " . number_format($score, 1) . "/100** (" . $color . ")\n\n";
      }
      $answer .= "**Detailed Metrics:**\n";
      if (isset($vldr_data['ref_domains'])) {
        $answer .= "• Referring Domains: ~" . number_format($vldr_data['ref_domains'] / 1000, 1) . "k\n";
      }
      if (isset($vldr_data['indexed_pages'])) {
        $answer .= "• Indexed Pages: ~" . number_format($vldr_data['indexed_pages'] / 1000, 1) . "k\n";
      }
      if (isset($vldr_data['lighthouse_avg'])) {
        $answer .= "• Lighthouse Average: " . $vldr_data['lighthouse_avg'] . "\n";
      }
      if (isset($vldr_data['security_grade'])) {
        $answer .= "• Security Grade: **" . $vldr_data['security_grade'] . "**\n";
      }
      if (isset($vldr_data['domain_age_years'])) {
        $answer .= "• Domain Age: " . number_format($vldr_data['domain_age_years'], 1) . " years\n";
      }
      if (isset($vldr_data['uptime_percent'])) {
        $answer .= "• Uptime: " . number_format($vldr_data['uptime_percent'], 2) . "%\n";
      }
      if (isset($vldr_data['metric_date'])) {
        $answer .= "\n*Last Updated: " . date('M j, Y', strtotime($vldr_data['metric_date'])) . "*\n";
      }
      $answer .= "\n*VL-DR is computed from public indicators: Common Crawl/Index, Bing Web Search, SecurityHeaders.com, WHOIS, Visible Light Uptime monitoring, and Lighthouse performance scores.*";
    } else {
      $answer = "I don't have domain ranking data for that domain. Make sure competitor analysis is set up in your Visible Light Hub profile for the domain you're asking about.";
    }
  }

  if ($answer === '') {
    $facts_source = isset($facts['__source']) ? $facts['__source'] : ((isset($facts['comprehensive']) && $facts['comprehensive']) ? 'comprehensive' : 'basic');
    if ($facts_source !== 'comprehensive') {
      $canned = luna_widget_find_canned_response($prompt);
      if (is_array($canned) && !empty($canned['content'])) {
        $answer = $canned['content'];
        $meta['source'] = 'canned_response';
        $meta['canned_id'] = $canned['id'];
        if (!empty($canned['title'])) {
          $meta['canned_title'] = $canned['title'];
        }
      }
    }
  }

  if ($answer === '') {
    $openai = luna_generate_openai_answer($pid, $prompt, $facts);
    if (is_array($openai) && !empty($openai['answer'])) {
      $answer = $openai['answer'];
      $meta['source'] = 'openai';
      if (!empty($openai['model'])) {
        $meta['model'] = $openai['model'];
      }
      if (!empty($openai['usage']) && is_array($openai['usage'])) {
        $meta['usage'] = $openai['usage'];
      }
    }
  }

  if ($answer === '') {
    $answer = "I can help you with information about your WordPress site, including themes, plugins, SSL status, security settings, domain information, and more. All data comes from your Visible Light Hub profile. What would you like to know?";
    $meta['source'] = 'default';
  }

  if ($pid) {
    $meta['conversation_id'] = $pid;
  }
  luna_log_turn($prompt, $answer, $meta);

  if ($is_composer) {
    luna_composer_log_entry($prompt, $answer, $meta, $pid);
  }

  return new WP_REST_Response(array('answer'=>$answer, 'meta'=>$meta), 200);
}

function luna_widget_rest_chat_inactive( WP_REST_Request $req ) {
  $default_message = "I haven't heard from you in a while, are you still there? If not, I'll close out this chat automatically in 3 minutes.";
  $message = $req->get_param('message');
  if (!is_string($message) || trim($message) === '') {
    $message = $default_message;
  } else {
    $message = sanitize_text_field($message);
  }

  $pid = luna_conv_id();
  $meta = array('source' => 'system', 'event' => 'inactive_warning');
  if ($pid) {
    $meta['conversation_id'] = $pid;
    update_post_meta($pid, 'last_inactive_warning', time());
  }

  luna_log_turn('', $message, $meta);

  return new WP_REST_Response(array('message' => $message), 200);
}

function luna_widget_rest_chat_end_session( WP_REST_Request $req ) {
  $pid = luna_conv_id();
  $default_message = 'This chat session has been closed due to inactivity.';
  $message = $req->get_param('message');
  if (!is_string($message) || trim($message) === '') {
    $message = $default_message;
  } else {
    $message = sanitize_text_field($message);
  }

  $reason = $req->get_param('reason');
  if (!is_string($reason) || trim($reason) === '') {
    $reason = 'manual';
  } else {
    $reason = sanitize_text_field($reason);
  }

  $already_closed = $pid ? (bool) get_post_meta($pid, 'session_closed', true) : false;
  if ($pid && !$already_closed) {
    luna_widget_close_conversation($pid, $reason);
    $meta = array(
      'source' => 'system',
      'event'  => 'session_end',
      'reason' => $reason,
      'conversation_id' => $pid,
    );
    luna_log_turn('', $message, $meta);
  }

  return new WP_REST_Response(array(
    'closed' => (bool) $pid,
    'already_closed' => $already_closed,
    'message' => $message,
  ), 200);
}

function luna_widget_rest_chat_reset_session( WP_REST_Request $req ) {
  $reason = $req->get_param('reason');
  if (!is_string($reason) || trim($reason) === '') {
    $reason = 'reset';
  } else {
    $reason = sanitize_text_field($reason);
  }

  $current = luna_widget_current_conversation_id();
  if ($current) {
    luna_widget_close_conversation($current, $reason);
  }

  $pid = luna_conv_id(true);
  if ($pid) {
    return new WP_REST_Response(array('reset' => true, 'conversation_id' => $pid), 200);
  }

  return new WP_REST_Response(array('reset' => false), 500);
}
add_action('rest_api_init', function () {

  /* --- CHAT --- */
  register_rest_route('luna_widget/v1', '/chat', array(
    'methods'  => 'POST',
    'permission_callback' => '__return_true',
    'callback' => 'luna_widget_chat_handler',
  ));

  /* --- TEST CHAT --- */
  register_rest_route('luna_widget/v1', '/test-chat', array(
    'methods'  => 'POST',
    'permission_callback' => '__return_true',
    'callback' => function( WP_REST_Request $req ){
      return new WP_REST_Response(array('answer'=>'Test successful!'), 200);
    },
  ));

  register_rest_route('luna_widget/v1', '/chat/inactive', array(
    'methods'  => 'POST',
    'permission_callback' => '__return_true',
    'callback' => 'luna_widget_rest_chat_inactive',
  ));

  register_rest_route('luna_widget/v1', '/chat/session/end', array(
    'methods'  => 'POST',
    'permission_callback' => '__return_true',
    'callback' => 'luna_widget_rest_chat_end_session',
  ));

  register_rest_route('luna_widget/v1', '/chat/session/reset', array(
    'methods'  => 'POST',
    'permission_callback' => '__return_true',
    'callback' => 'luna_widget_rest_chat_reset_session',
  ));

  /* --- HISTORY (hydrate UI after reloads) --- */
  register_rest_route('luna_widget/v1', '/chat/history', array(
    'methods'  => 'GET',
    'permission_callback' => '__return_true',
    'callback' => function( WP_REST_Request $req ){
      $pid = luna_conv_id();
      if (!$pid) return new WP_REST_Response(array('items'=>array()), 200);
      $t = get_post_meta($pid, 'transcript', true); if (!is_array($t)) $t = array();
      $limit = max(1, min(50, (int)$req->get_param('limit') ? (int)$req->get_param('limit') : 20));
      $slice = array_slice($t, -$limit);
      $items = array();
      foreach ($slice as $row) {
        $items[] = array(
          'ts'        => isset($row['ts']) ? (int)$row['ts'] : 0,
          'ts_iso'    => !empty($row['ts']) ? gmdate('c', (int)$row['ts']) : null,
          'user'      => isset($row['user']) ? wp_strip_all_tags((string)$row['user']) : '',
          'assistant' => isset($row['assistant']) ? wp_strip_all_tags((string)$row['assistant']) : '',
        );
      }
      return new WP_REST_Response(array('items'=>$items), 200);
    },
  ));

  /* --- Hub-facing list endpoints (license-gated) --- */
  $secure_cb = function(){ return true; };

  // System snapshot (plugins/themes summary here)
  register_rest_route('luna_widget/v1', '/system/site', array(
    'methods'  => 'GET',
    'permission_callback' => $secure_cb,
    'callback' => function( WP_REST_Request $req ){
      if (!luna_license_ok($req)) return luna_forbidden();
      return new WP_REST_Response( luna_snapshot_system(), 200 );
    },
  ));
  // Aliases some hubs expect
  register_rest_route('vl-hub/v1', '/system/site', array(
    'methods'  => 'GET',
    'permission_callback' => $secure_cb,
    'callback' => function( WP_REST_Request $req ){
      if (!luna_license_ok($req)) return luna_forbidden();
      return new WP_REST_Response( luna_snapshot_system(), 200 );
    },
  ));

  // Enhanced Posts endpoint with SEO scores, meta data, and detailed author info
  $posts_cb = function( WP_REST_Request $req ){
    if (!luna_license_ok($req)) return luna_forbidden();
    $per  = max(1, min(200, (int)$req->get_param('per_page') ?: 50));
    $page = max(1, (int)$req->get_param('page') ?: 1);
    $q = new WP_Query(array(
      'post_type'      => 'post',
      'post_status'    => 'publish',
      'posts_per_page' => $per,
      'paged'          => $page,
      'orderby'        => 'date',
      'order'          => 'DESC',
      'fields'         => 'ids',
    ));
    $items = array();
    foreach ($q->posts as $pid) {
      $cats = wp_get_post_terms($pid, 'category', array('fields'=>'names'));
      $tags = wp_get_post_terms($pid, 'post_tag', array('fields'=>'names'));
      $author_id = get_post_field('post_author', $pid);
      $author = get_user_by('id', $author_id);
      
      // Get meta data
      $meta_data = get_post_meta($pid);
      
      // Calculate SEO score (basic implementation)
      $seo_score = luna_calculate_seo_score($pid);
      
      $items[] = array(
        'id'        => $pid,
        'title'     => get_the_title($pid),
        'slug'      => get_post_field('post_name', $pid),
        'date'      => get_post_time('c', true, $pid),
        'author'    => array(
          'id' => $author_id,
          'username' => $author ? $author->user_login : 'Unknown',
          'email' => $author ? $author->user_email : '',
          'display_name' => $author ? $author->display_name : 'Unknown'
        ),
        'categories'=> array_values($cats ?: array()),
        'tags'      => array_values($tags ?: array()),
        'permalink' => get_permalink($pid),
        'meta_data' => $meta_data,
        'seo_score' => $seo_score,
        'status'    => get_post_status($pid),
        'comment_count' => get_comments_number($pid),
        'featured_image' => get_the_post_thumbnail_url($pid, 'full')
      );
    }
    return new WP_REST_Response(array('total'=>(int)$q->found_posts,'page'=>$page,'per_page'=>$per,'items'=>$items), 200);
  };
  register_rest_route('luna_widget/v1', '/content/posts', array('methods'=>'GET','permission_callback'=>$secure_cb,'callback'=>$posts_cb));
  register_rest_route('vl-hub/v1',      '/posts',         array('methods'=>'GET','permission_callback'=>$secure_cb,'callback'=>$posts_cb));

  // Enhanced Pages endpoint with SEO scores, meta data, and detailed author info
  $pages_cb = function( WP_REST_Request $req ){
    if (!luna_license_ok($req)) return luna_forbidden();
    $per  = max(1, min(200, (int)$req->get_param('per_page') ?: 50));
    $page = max(1, (int)$req->get_param('page') ?: 1);
    $q = new WP_Query(array(
      'post_type'      => 'page',
      'post_status'    => array('publish', 'draft', 'private', 'pending'),
      'posts_per_page' => $per,
      'paged'          => $page,
      'orderby'        => 'date',
      'order'          => 'DESC',
      'fields'         => 'ids',
    ));
    $items = array();
    foreach ($q->posts as $pid) {
      $author_id = get_post_field('post_author', $pid);
      $author = get_user_by('id', $author_id);
      
      // Get meta data
      $meta_data = get_post_meta($pid);
      
      // Calculate SEO score (basic implementation)
      $seo_score = luna_calculate_seo_score($pid);
      
      $items[] = array(
        'id'        => $pid,
        'title'     => get_the_title($pid),
        'slug'      => get_post_field('post_name', $pid),
        'status'    => get_post_status($pid),
        'date'      => get_post_time('c', true, $pid),
        'author'    => array(
          'id' => $author_id,
          'username' => $author ? $author->user_login : 'Unknown',
          'email' => $author ? $author->user_email : '',
          'display_name' => $author ? $author->display_name : 'Unknown'
        ),
        'permalink' => get_permalink($pid),
        'meta_data' => $meta_data,
        'seo_score' => $seo_score,
        'comment_count' => get_comments_number($pid),
        'featured_image' => get_the_post_thumbnail_url($pid, 'full'),
        'parent' => get_post_field('post_parent', $pid)
      );
    }
    return new WP_REST_Response(array('total'=>(int)$q->found_posts,'page'=>$page,'per_page'=>$per,'items'=>$items), 200);
  };
  register_rest_route('luna_widget/v1', '/content/pages', array('methods'=>'GET','permission_callback'=>$secure_cb,'callback'=>$pages_cb));
  register_rest_route('vl-hub/v1',      '/pages',         array('methods'=>'GET','permission_callback'=>$secure_cb,'callback'=>$pages_cb));

  // Enhanced Users endpoint with detailed user information
  $users_cb = function( WP_REST_Request $req ){
    if (!luna_license_ok($req)) return luna_forbidden();
    $per    = max(1, min(200, (int)$req->get_param('per_page') ?: 100));
    $page   = max(1, (int)$req->get_param('page') ?: 1);
    $offset = ($page-1)*$per;
    $u = get_users(array(
      'number' => $per,
      'offset' => $offset,
      'fields' => array('user_login','user_email','display_name','ID','user_registered','user_url'),
      'orderby'=> 'ID',
      'order'  => 'ASC',
    ));
    $items = array();
    foreach ($u as $row) {
      $user_meta = get_user_meta($row->ID);
      $items[] = array(
        'id'       => (int)$row->ID,
        'username' => $row->user_login,
        'email'    => $row->user_email,
        'name'     => $row->display_name,
        'url'      => $row->user_url,
        'registered' => $row->user_registered,
        'roles'    => get_userdata($row->ID)->roles,
        'last_login' => get_user_meta($row->ID, 'last_login', true),
        'post_count' => count_user_posts($row->ID),
        'meta_data' => $user_meta
      );
    }
    $counts = count_users();
    $total  = isset($counts['total_users']) ? (int)$counts['total_users'] : (int)($offset + count($items));
    return new WP_REST_Response(array('total'=>$total,'page'=>$page,'per_page'=>$per,'items'=>$items), 200);
  };
  register_rest_route('luna_widget/v1', '/users', array('methods'=>'GET','permission_callback'=>$secure_cb,'callback'=>$users_cb));
  register_rest_route('vl-hub/v1',      '/users', array('methods'=>'GET','permission_callback'=>$secure_cb,'callback'=>$users_cb));

  // Plugins
  register_rest_route('luna_widget/v1', '/plugins', array(
    'methods'  => 'GET',
    'permission_callback' => $secure_cb,
    'callback' => function( WP_REST_Request $req ){
      if (!luna_license_ok($req)) return luna_forbidden();
      if (!function_exists('get_plugins')) { @require_once ABSPATH . 'wp-admin/includes/plugin.php'; }
      $plugins = function_exists('get_plugins') ? (array)get_plugins() : array();
      $active  = (array) get_option('active_plugins', array());
      $up_pl   = get_site_transient('update_plugins');
      $items = array();
      foreach ($plugins as $slug => $info) {
        $update_available = isset($up_pl->response[$slug]);
        $items[] = array(
          'slug'            => $slug,
          'name'            => isset($info['Name']) ? $info['Name'] : $slug,
          'version'         => isset($info['Version']) ? $info['Version'] : null,
          'active'          => in_array($slug, $active, true),
          'update_available'=> (bool)$update_available,
          'new_version'     => $update_available ? (isset($up_pl->response[$slug]->new_version) ? $up_pl->response[$slug]->new_version : null) : null,
        );
      }
      return new WP_REST_Response(array('items'=>$items), 200);
    },
  ));

  // Themes
  register_rest_route('luna_widget/v1', '/themes', array(
    'methods'  => 'GET',
    'permission_callback' => $secure_cb,
    'callback' => function( WP_REST_Request $req ){
      if (!luna_license_ok($req)) return luna_forbidden();
      $themes = wp_get_themes();
      $up_th  = get_site_transient('update_themes');
      $active_stylesheet = wp_get_theme()->get_stylesheet();
      $items = array();
      foreach ($themes as $stylesheet => $th) {
        $update_available = isset($up_th->response[$stylesheet]);
        $items[] = array(
          'stylesheet'      => $stylesheet,
          'name'            => $th->get('Name'),
          'version'         => $th->get('Version'),
          'is_active'       => ($active_stylesheet === $stylesheet),
          'update_available'=> (bool)$update_available,
          'new_version'     => $update_available ? (isset($up_th->response[$stylesheet]['new_version']) ? $up_th->response[$stylesheet]['new_version'] : null) : null,
        );
      }
      return new WP_REST_Response(array('items'=>$items), 200);
    },
  ));

  /* Utilities: manual pings */
  register_rest_route('luna_widget/v1', '/ping-hub', array(
    'methods'  => 'POST',
    'permission_callback' => function(){ return current_user_can('manage_options'); },
    'callback' => function(){
      luna_widget_try_activation();
      $last = get_option(LUNA_WIDGET_OPT_LAST_PING, array());
      return new WP_REST_Response(array('ok'=>true,'last'=>$last), 200);
    },
  ));
  register_rest_route('luna_widget/v1', '/heartbeat-now', array(
    'methods'  => 'POST',
    'permission_callback' => function(){ return current_user_can('manage_options'); },
    'callback' => function(){
      luna_widget_send_heartbeat();
      $last = get_option(LUNA_WIDGET_OPT_LAST_PING, array());
      return new WP_REST_Response(array('ok'=>true,'last'=>$last), 200);
    },
  ));

  /* --- Purge profile cache (Hub → client after Security edits) --- */
  register_rest_route('luna_widget/v1', '/purge-profile-cache', array(
    'methods'  => 'POST',
    'permission_callback' => '__return_true',
    'callback' => function (WP_REST_Request $req) {
      if (!luna_license_ok($req)) return new WP_REST_Response(array('ok'=>false,'error'=>'forbidden'), 403);
      luna_profile_cache_bust(true);
      return new WP_REST_Response(array('ok'=>true,'message'=>'Profile cache purged'), 200);
    },
  ));

  /* --- Debug endpoint to test Hub connection --- */
  register_rest_route('luna_widget/v1', '/debug-hub', array(
    'methods'  => 'GET',
    'permission_callback' => '__return_true',
    'callback' => function (WP_REST_Request $req) {
      $license = luna_get_license();
      $hub_url = luna_widget_hub_base();
      $endpoint = $hub_url . '/wp-json/luna_widget/v1/system/comprehensive';
      
      $response = wp_remote_get($endpoint, array(
        'headers' => array('X-Luna-License' => $license),
        'timeout' => 10
      ));
      
      $debug_info = array(
        'license' => $license ? substr($license, 0, 8) . '...' : 'NOT SET',
        'hub_url' => $hub_url,
        'endpoint' => $endpoint,
        'is_error' => is_wp_error($response),
        'error_message' => is_wp_error($response) ? $response->get_error_message() : null,
        'response_code' => is_wp_error($response) ? null : wp_remote_retrieve_response_code($response),
        'response_body' => is_wp_error($response) ? null : wp_remote_retrieve_body($response),
      );
      
      return new WP_REST_Response($debug_info, 200);
    },
  ));

  /* --- Debug endpoint to see comprehensive facts --- */
  register_rest_route('luna_widget/v1', '/debug-facts', array(
    'methods'  => 'GET',
    'permission_callback' => '__return_true',
    'callback' => function (WP_REST_Request $req) {
      $facts = luna_profile_facts_comprehensive();
      
      $debug_info = array(
        'comprehensive_facts' => $facts,
        'has_pages' => isset($facts['pages']) && is_array($facts['pages']) ? count($facts['pages']) : 0,
        'has_themes' => isset($facts['themes']) && is_array($facts['themes']) ? count($facts['themes']) : 0,
        'updates' => $facts['updates'] ?? array(),
        'counts' => $facts['counts'] ?? array(),
      );
      
      return new WP_REST_Response($debug_info, 200);
    },
  ));

  /* --- Debug endpoint to test regex patterns --- */
  register_rest_route('luna_widget/v1', '/debug-regex', array(
    'methods'  => 'GET',
    'permission_callback' => '__return_true',
    'callback' => function (WP_REST_Request $req) {
      $test_phrases = array(
        'What are the names of the pages?',
        'What are the names of the posts?',
        'Do I have any inactive pages?',
        'What themes do I have?'
      );
      
      $results = array();
      foreach ($test_phrases as $phrase) {
        $lc = strtolower($phrase);
        $results[$phrase] = array(
          'lowercase' => $lc,
          'page_names_match' => preg_match('/\bnames.*of.*pages|page.*names|what.*are.*the.*names.*of.*pages\b/', $lc),
          'post_names_match' => preg_match('/\bnames.*of.*posts|post.*names|what.*are.*the.*names.*of.*posts\b/', $lc),
          'inactive_pages_match' => preg_match('/\binactive.*page|page.*inactive|draft.*page|page.*draft\b/', $lc),
          'theme_list_match' => preg_match('/\binactive.*theme|theme.*inactive|what.*themes|list.*themes|all.*themes\b/', $lc)
        );
      }
      
      return new WP_REST_Response($results, 200);
    },
  ));

  /* --- Debug endpoint for keyword mappings --- */
  register_rest_route('luna_widget/v1', '/debug-keywords', array(
    'methods'  => 'GET',
    'permission_callback' => '__return_true',
    'callback' => function (WP_REST_Request $req) {
      $test_input = $req->get_param('input') ?: 'hey Lu';
      $mappings = luna_get_keyword_mappings();
      $keyword_match = luna_check_keyword_mappings($test_input);
      
      return new WP_REST_Response(array(
        'test_input' => $test_input,
        'mappings' => $mappings,
        'keyword_match' => $keyword_match,
        'mapping_count' => count($mappings)
      ), 200);
    },
  ));

  /* --- Comprehensive WordPress Data Collection Endpoints --- */
  
  // Comments endpoint
  register_rest_route('luna_widget/v1', '/comments', array(
    'methods'  => 'GET',
    'permission_callback' => $secure_cb,
    'callback' => function( WP_REST_Request $req ){
      if (!luna_license_ok($req)) return luna_forbidden();
      $per_page = max(1, min(200, (int)$req->get_param('per_page') ?: 50));
      $page = max(1, (int)$req->get_param('page') ?: 1);
      $comments = get_comments(array(
        'number' => $per_page,
        'offset' => ($page - 1) * $per_page,
        'status' => 'approve'
      ));
      $items = array();
      foreach ($comments as $comment) {
        $items[] = array(
          'id' => $comment->comment_ID,
          'post_id' => $comment->comment_post_ID,
          'author' => $comment->comment_author,
          'author_email' => $comment->comment_author_email,
          'author_url' => $comment->comment_author_url,
          'content' => $comment->comment_content,
          'date' => $comment->comment_date,
          'approved' => $comment->comment_approved,
          'type' => $comment->comment_type,
          'parent' => $comment->comment_parent
        );
      }
      return new WP_REST_Response(array('items'=>$items), 200);
    },
  ));

  // Media endpoint
  register_rest_route('luna_widget/v1', '/media', array(
    'methods'  => 'GET',
    'permission_callback' => $secure_cb,
    'callback' => function( WP_REST_Request $req ){
      if (!luna_license_ok($req)) return luna_forbidden();
      $per_page = max(1, min(200, (int)$req->get_param('per_page') ?: 50));
      $page = max(1, (int)$req->get_param('page') ?: 1);
      $query = new WP_Query(array(
        'post_type' => 'attachment',
        'post_status' => 'inherit',
        'posts_per_page' => $per_page,
        'paged' => $page,
        'orderby' => 'date',
        'order' => 'DESC'
      ));
      $items = array();
      foreach ($query->posts as $attachment) {
        $file_path = get_attached_file($attachment->ID);
        $items[] = array(
          'id' => $attachment->ID,
          'title' => $attachment->post_title,
          'filename' => basename($file_path),
          'mime_type' => $attachment->post_mime_type,
          'url' => wp_get_attachment_url($attachment->ID),
          'date' => $attachment->post_date,
          'author' => get_the_author_meta('user_login', $attachment->post_author),
          'file_size' => $file_path && file_exists($file_path) ? filesize($file_path) : 0
        );
      }
      return new WP_REST_Response(array('items'=>$items), 200);
    },
  ));

  // Categories endpoint
  register_rest_route('luna_widget/v1', '/categories', array(
    'methods'  => 'GET',
    'permission_callback' => $secure_cb,
    'callback' => function( WP_REST_Request $req ){
      if (!luna_license_ok($req)) return luna_forbidden();
      $categories = get_categories(array('hide_empty' => false));
      $items = array();
      foreach ($categories as $category) {
        $items[] = array(
          'id' => $category->term_id,
          'name' => $category->name,
          'slug' => $category->slug,
          'description' => $category->description,
          'count' => $category->count,
          'parent' => $category->parent
        );
      }
      return new WP_REST_Response(array('items'=>$items), 200);
    },
  ));

  // Tags endpoint
  register_rest_route('luna_widget/v1', '/tags', array(
    'methods'  => 'GET',
    'permission_callback' => $secure_cb,
    'callback' => function( WP_REST_Request $req ){
      if (!luna_license_ok($req)) return luna_forbidden();
      $tags = get_tags(array('hide_empty' => false));
      $items = array();
      foreach ($tags as $tag) {
        $items[] = array(
          'id' => $tag->term_id,
          'name' => $tag->name,
          'slug' => $tag->slug,
          'description' => $tag->description,
          'count' => $tag->count
        );
      }
      return new WP_REST_Response(array('items'=>$items), 200);
    },
  ));

  // Custom post types endpoint
  register_rest_route('luna_widget/v1', '/custom-post-types', array(
    'methods'  => 'GET',
    'permission_callback' => $secure_cb,
    'callback' => function( WP_REST_Request $req ){
      if (!luna_license_ok($req)) return luna_forbidden();
      $post_types = get_post_types(array('public' => true), 'objects');
      $items = array();
      foreach ($post_types as $post_type) {
        if ($post_type->name === 'attachment') continue;
        $count = wp_count_posts($post_type->name);
        $items[] = array(
          'name' => $post_type->name,
          'label' => $post_type->label,
          'description' => $post_type->description,
          'public' => $post_type->public,
          'hierarchical' => $post_type->hierarchical,
          'count' => array(
            'publish' => $count->publish,
            'draft' => $count->draft,
            'private' => $count->private,
            'trash' => $count->trash
          )
        );
      }
      return new WP_REST_Response(array('items'=>$items), 200);
    },
  ));

  // Menus endpoint
  register_rest_route('luna_widget/v1', '/menus', array(
    'methods'  => 'GET',
    'permission_callback' => $secure_cb,
    'callback' => function( WP_REST_Request $req ){
      if (!luna_license_ok($req)) return luna_forbidden();
      $menus = wp_get_nav_menus();
      $items = array();
      foreach ($menus as $menu) {
        $items[] = array(
          'id' => $menu->term_id,
          'name' => $menu->name,
          'slug' => $menu->slug,
          'description' => $menu->description,
          'count' => $menu->count
        );
      }
      return new WP_REST_Response(array('items'=>$items), 200);
    },
  ));

  // Widgets endpoint
  register_rest_route('luna_widget/v1', '/widgets', array(
    'methods'  => 'GET',
    'permission_callback' => $secure_cb,
    'callback' => function( WP_REST_Request $req ){
      if (!luna_license_ok($req)) return luna_forbidden();
      global $wp_registered_widgets;
      $items = array();
      foreach ($wp_registered_widgets as $widget_id => $widget) {
        $items[] = array(
          'id' => $widget_id,
          'name' => $widget['name'],
          'class' => $widget['classname'],
          'description' => $widget['description']
        );
      }
      return new WP_REST_Response(array('items'=>$items), 200);
    },
  ));

  // Sidebars endpoint
  register_rest_route('luna_widget/v1', '/sidebars', array(
    'methods'  => 'GET',
    'permission_callback' => $secure_cb,
    'callback' => function( WP_REST_Request $req ){
      if (!luna_license_ok($req)) return luna_forbidden();
      global $wp_registered_sidebars;
      $items = array();
      foreach ($wp_registered_sidebars as $sidebar_id => $sidebar) {
        $items[] = array(
          'id' => $sidebar_id,
          'name' => $sidebar['name'],
          'description' => $sidebar['description'],
          'class' => $sidebar['class'],
          'before_widget' => $sidebar['before_widget'],
          'after_widget' => $sidebar['after_widget'],
          'before_title' => $sidebar['before_title'],
          'after_title' => $sidebar['after_title']
        );
      }
      return new WP_REST_Response(array('items'=>$items), 200);
    },
  ));

  // Options endpoint
  register_rest_route('luna_widget/v1', '/options', array(
    'methods'  => 'GET',
    'permission_callback' => $secure_cb,
    'callback' => function( WP_REST_Request $req ){
      if (!luna_license_ok($req)) return luna_forbidden();
      $options = array(
        'site_name' => get_option('blogname'),
        'site_description' => get_option('blogdescription'),
        'admin_email' => get_option('admin_email'),
        'timezone' => get_option('timezone_string'),
        'date_format' => get_option('date_format'),
        'time_format' => get_option('time_format'),
        'start_of_week' => get_option('start_of_week'),
        'language' => get_option('WPLANG'),
        'permalink_structure' => get_option('permalink_structure'),
        'default_category' => get_option('default_category'),
        'default_post_format' => get_option('default_post_format'),
        'users_can_register' => get_option('users_can_register'),
        'default_role' => get_option('default_role'),
        'comment_moderation' => get_option('comment_moderation'),
        'comment_registration' => get_option('comment_registration'),
        'close_comments_for_old_posts' => get_option('close_comments_for_old_posts'),
        'close_comments_days_old' => get_option('close_comments_days_old'),
        'thread_comments' => get_option('thread_comments'),
        'thread_comments_depth' => get_option('thread_comments_depth'),
        'page_comments' => get_option('page_comments'),
        'comments_per_page' => get_option('comments_per_page'),
        'default_comments_page' => get_option('default_comments_page'),
        'comment_order' => get_option('comment_order')
      );
      return new WP_REST_Response(array('options'=>$options), 200);
    },
  ));

  // Database tables endpoint
  register_rest_route('luna_widget/v1', '/database-tables', array(
    'methods'  => 'GET',
    'permission_callback' => $secure_cb,
    'callback' => function( WP_REST_Request $req ){
      if (!luna_license_ok($req)) return luna_forbidden();
      global $wpdb;
      $tables = $wpdb->get_results("SHOW TABLES", ARRAY_N);
      $items = array();
      foreach ($tables as $table) {
        $table_name = $table[0];
        $count = $wpdb->get_var("SELECT COUNT(*) FROM `$table_name`");
        $items[] = array(
          'name' => $table_name,
          'count' => (int)$count
        );
      }
      return new WP_REST_Response(array('items'=>$items), 200);
    },
  ));

  // WordPress Core Status endpoint
  register_rest_route('luna_widget/v1', '/wp-core-status', array(
    'methods'  => 'GET',
    'permission_callback' => $secure_cb,
    'callback' => function( WP_REST_Request $req ){
      if (!luna_license_ok($req)) return luna_forbidden();
      
      global $wp_version;
      $core_updates = get_site_transient('update_core');
      $is_update_available = !empty($core_updates->updates) && $core_updates->updates[0]->response === 'upgrade';
      
      $status = array(
        'version' => $wp_version,
        'update_available' => $is_update_available,
        'latest_version' => $is_update_available ? $core_updates->updates[0]->version : $wp_version,
        'php_version' => PHP_VERSION,
        'mysql_version' => $GLOBALS['wpdb']->db_version(),
        'memory_limit' => ini_get('memory_limit'),
        'max_execution_time' => ini_get('max_execution_time'),
        'upload_max_filesize' => ini_get('upload_max_filesize'),
        'post_max_size' => ini_get('post_max_size'),
        'max_input_vars' => ini_get('max_input_vars'),
        'is_multisite' => is_multisite(),
        'site_url' => get_site_url(),
        'home_url' => get_home_url(),
        'admin_email' => get_option('admin_email'),
        'timezone' => get_option('timezone_string'),
        'date_format' => get_option('date_format'),
        'time_format' => get_option('time_format'),
        'start_of_week' => get_option('start_of_week'),
        'language' => get_option('WPLANG'),
        'permalink_structure' => get_option('permalink_structure'),
        'users_can_register' => get_option('users_can_register'),
        'default_role' => get_option('default_role'),
        'comment_moderation' => get_option('comment_moderation'),
        'comment_registration' => get_option('comment_registration'),
        'close_comments_for_old_posts' => get_option('close_comments_for_old_posts'),
        'close_comments_days_old' => get_option('close_comments_days_old'),
        'thread_comments' => get_option('thread_comments'),
        'thread_comments_depth' => get_option('thread_comments_depth'),
        'page_comments' => get_option('page_comments'),
        'comments_per_page' => get_option('comments_per_page'),
        'default_comments_page' => get_option('default_comments_page'),
        'comment_order' => get_option('comment_order')
      );
      
      return new WP_REST_Response($status, 200);
    },
  ));

  // Comments count endpoint
  register_rest_route('luna_widget/v1', '/comments-count', array(
    'methods'  => 'GET',
    'permission_callback' => $secure_cb,
    'callback' => function( WP_REST_Request $req ){
      if (!luna_license_ok($req)) return luna_forbidden();
      
      $counts = wp_count_comments();
      $total = $counts->total_comments;
      $approved = $counts->approved;
      $pending = $counts->moderated;
      $spam = $counts->spam;
      $trash = $counts->trash;
      
      return new WP_REST_Response(array(
        'total' => $total,
        'approved' => $approved,
        'pending' => $pending,
        'spam' => $spam,
        'trash' => $trash
      ), 200);
    },
  ));

  // All WordPress data endpoint (comprehensive collection)
  register_rest_route('luna_widget/v1', '/all-wp-data', array(
    'methods'  => 'GET',
    'permission_callback' => $secure_cb,
    'callback' => function( WP_REST_Request $req ){
      if (!luna_license_ok($req)) return luna_forbidden();
      
      $data = array();
      
      // System info
      $data['system'] = luna_snapshot_system();
      
      // Posts (limited to 100 most recent)
      $posts_query = new WP_Query(array(
        'post_type' => 'post',
        'post_status' => 'publish',
        'posts_per_page' => 100,
        'orderby' => 'date',
        'order' => 'DESC',
        'fields' => 'ids'
      ));
      $data['posts'] = array();
      foreach ($posts_query->posts as $pid) {
        $data['posts'][] = array(
          'id' => $pid,
          'title' => get_the_title($pid),
          'excerpt' => get_the_excerpt($pid),
          'date' => get_the_date('c', $pid),
          'author' => get_the_author_meta('user_login', get_post_field('post_author', $pid)),
          'categories' => wp_get_post_terms($pid, 'category', array('fields'=>'names')),
          'tags' => wp_get_post_terms($pid, 'post_tag', array('fields'=>'names'))
        );
      }
      
      // Pages (limited to 100 most recent)
      $pages_query = new WP_Query(array(
        'post_type' => 'page',
        'post_status' => 'publish',
        'posts_per_page' => 100,
        'orderby' => 'date',
        'order' => 'DESC',
        'fields' => 'ids'
      ));
      $data['pages'] = array();
      foreach ($pages_query->posts as $pid) {
        $data['pages'][] = array(
          'id' => $pid,
          'title' => get_the_title($pid),
          'excerpt' => get_the_excerpt($pid),
          'date' => get_the_date('c', $pid),
          'author' => get_the_author_meta('user_login', get_post_field('post_author', $pid)),
          'parent' => get_post_field('post_parent', $pid)
        );
      }
      
      // Users (limited to 50 most recent)
      $users = get_users(array('number' => 50, 'orderby' => 'registered', 'order' => 'DESC'));
      $data['users'] = array();
      foreach ($users as $user) {
        $data['users'][] = array(
          'id' => $user->ID,
          'login' => $user->user_login,
          'email' => $user->user_email,
          'display_name' => $user->display_name,
          'roles' => $user->roles,
          'registered' => $user->user_registered,
          'last_login' => get_user_meta($user->ID, 'last_login', true)
        );
      }
      
      // Comments (limited to 100 most recent)
      $comments = get_comments(array('number' => 100, 'status' => 'approve'));
      $data['comments'] = array();
      foreach ($comments as $comment) {
        $data['comments'][] = array(
          'id' => $comment->comment_ID,
          'post_id' => $comment->comment_post_ID,
          'author' => $comment->comment_author,
          'content' => $comment->comment_content,
          'date' => $comment->comment_date,
          'approved' => $comment->comment_approved
        );
      }
      
      // Media (limited to 100 most recent)
      $media_query = new WP_Query(array(
        'post_type' => 'attachment',
        'post_status' => 'inherit',
        'posts_per_page' => 100,
        'orderby' => 'date',
        'order' => 'DESC'
      ));
      $data['media'] = array();
      foreach ($media_query->posts as $attachment) {
        $data['media'][] = array(
          'id' => $attachment->ID,
          'title' => $attachment->post_title,
          'filename' => basename(get_attached_file($attachment->ID)),
          'mime_type' => $attachment->post_mime_type,
          'url' => wp_get_attachment_url($attachment->ID),
          'date' => $attachment->post_date
        );
      }
      
      // Categories
      $categories = get_categories(array('hide_empty' => false));
      $data['categories'] = array();
      foreach ($categories as $category) {
        $data['categories'][] = array(
          'id' => $category->term_id,
          'name' => $category->name,
          'slug' => $category->slug,
          'count' => $category->count
        );
      }
      
      // Tags
      $tags = get_tags(array('hide_empty' => false));
      $data['tags'] = array();
      foreach ($tags as $tag) {
        $data['tags'][] = array(
          'id' => $tag->term_id,
          'name' => $tag->name,
          'slug' => $tag->slug,
          'count' => $tag->count
        );
      }
      
      // Custom post types
      $post_types = get_post_types(array('public' => true), 'objects');
      $data['custom_post_types'] = array();
      foreach ($post_types as $post_type) {
        if ($post_type->name === 'attachment') continue;
        $count = wp_count_posts($post_type->name);
        $data['custom_post_types'][] = array(
          'name' => $post_type->name,
          'label' => $post_type->label,
          'count' => array(
            'publish' => $count->publish,
            'draft' => $count->draft,
            'private' => $count->private
          )
        );
      }
      
      // Menus
      $menus = wp_get_nav_menus();
      $data['menus'] = array();
      foreach ($menus as $menu) {
        $data['menus'][] = array(
          'id' => $menu->term_id,
          'name' => $menu->name,
          'count' => $menu->count
        );
      }
      
      // Site options
      $data['options'] = array(
        'site_name' => get_option('blogname'),
        'site_description' => get_option('blogdescription'),
        'admin_email' => get_option('admin_email'),
        'timezone' => get_option('timezone_string'),
        'language' => get_option('WPLANG'),
        'permalink_structure' => get_option('permalink_structure'),
        'users_can_register' => get_option('users_can_register'),
        'default_role' => get_option('default_role')
      );
      
      return new WP_REST_Response($data, 200);
    },
  ));

  /* --- Sync to Hub endpoint --- */
  register_rest_route('luna_widget/v1', '/sync-to-hub', array(
    'methods'  => 'POST',
    'permission_callback' => function(){ return current_user_can('manage_options'); },
    'callback' => function(){
      $license = luna_get_license();
      if (!$license) {
        return new WP_REST_Response(array('ok'=>false,'error'=>'No license found'), 400);
      }
      
      // Sync all data to Hub
      $settings_data = array(
        'license' => $license,
        'hub_url' => luna_widget_hub_base(),
        'mode' => get_option(LUNA_WIDGET_OPT_MODE, 'widget'),
        'ui_settings' => get_option(LUNA_WIDGET_OPT_SETTINGS, array()),
        'wp_version' => get_bloginfo('version'),
        'plugin_version' => LUNA_WIDGET_PLUGIN_VERSION,
        'site_url' => home_url('/'),
        'last_sync' => current_time('mysql')
      );
      
      luna_sync_settings_to_hub($settings_data);
      
      // Sync keywords
      $keywords = luna_get_keyword_mappings();
      luna_sync_keywords_to_hub($keywords);
      
      // Sync analytics settings
      $analytics = get_option('luna_ga4_settings', array());
      if (!empty($analytics)) {
        luna_sync_analytics_to_hub($analytics);
      }
      
      return new WP_REST_Response(array('ok'=>true,'message'=>'All data synced to Hub'), 200);
    },
  ));
});

// AJAX handler for Luna Widget chat transcript
add_action('wp_ajax_luna_get_chat_transcript', function() {
  check_ajax_referer('luna_chat_transcript_nonce', 'nonce');
  
  $license_key = sanitize_text_field($_POST['license_key'] ?? '');
  if (empty($license_key)) {
    wp_send_json_error('License key required');
    return;
  }
  
  $transcript = luna_get_chat_transcript($license_key);
  wp_send_json_success(array('transcript' => $transcript));
});

/* ============================================================
 * KEYWORD MAPPING SYSTEM
 * ============================================================ */

// Default keyword mappings with response templates
function luna_get_default_keywords() {
  return [
    'business' => [
      'appointment' => [
        'enabled' => 'on',
        'keywords' => ['booking', 'schedule', 'visit', 'consultation'],
        'template' => 'To schedule an appointment, please call our office or use our online booking system. You can find our contact information on our website.',
        'data_source' => 'custom'
      ],
      'contact' => [
        'enabled' => 'on',
        'keywords' => ['phone', 'email', 'reach', 'get in touch'],
        'template' => 'You can reach us through our contact page or by calling our main office number. Our contact information is available on our website.',
        'data_source' => 'custom'
      ],
      'hours' => [
        'enabled' => 'on',
        'keywords' => ['open', 'closed', 'business hours', 'availability'],
        'template' => 'Our business hours are typically Monday through Friday, 9 AM to 5 PM. Please check our website for the most current hours and holiday schedules.',
        'data_source' => 'custom'
      ],
      'location' => [
        'enabled' => 'on',
        'keywords' => ['address', 'where', 'directions', 'find us'],
        'template' => 'You can find our address and directions on our website\'s contact page. We\'re located in a convenient area with parking available.',
        'data_source' => 'custom'
      ],
      'services' => [
        'enabled' => 'on',
        'keywords' => ['what we do', 'offerings', 'treatments', 'care'],
        'template' => 'We offer a comprehensive range of services. Please visit our services page on our website for detailed information about what we provide.',
        'data_source' => 'custom'
      ],
      'providers' => [
        'enabled' => 'on',
        'keywords' => ['doctors', 'staff', 'team', 'physicians'],
        'template' => 'Our team of experienced providers is dedicated to your care. You can learn more about our staff on our website\'s team page.',
        'data_source' => 'custom'
      ],
      'insurance' => [
        'enabled' => 'on',
        'keywords' => ['coverage', 'accepted', 'billing', 'payment'],
        'template' => 'We accept most major insurance plans. Please contact our billing department to verify your coverage and discuss payment options.',
        'data_source' => 'custom'
      ],
      'forms' => [
        'enabled' => 'on',
        'keywords' => ['paperwork', 'documents', 'download', 'patient forms'],
        'template' => 'You can download patient forms from our website or pick them up at our office. Please complete them before your visit to save time.',
        'data_source' => 'custom'
      ]
    ],
    'wp_rest' => [
      'pages' => [
        'enabled' => 'on',
        'keywords' => ['page names', 'what pages', 'list pages', 'site pages'],
        'template' => 'Your pages are: {pages_list}.',
        'data_source' => 'wp_rest'
      ],
      'posts' => [
        'enabled' => 'on',
        'keywords' => ['blog posts', 'articles', 'news', 'content'],
        'template' => 'Your posts are: {posts_list}.',
        'data_source' => 'wp_rest'
      ],
      'themes' => [
        'enabled' => 'on',
        'keywords' => ['theme info', 'design', 'appearance', 'look'],
        'template' => 'Your themes are: {themes_list}.',
        'data_source' => 'wp_rest'
      ],
      'plugins' => [
        'enabled' => 'on',
        'keywords' => ['add-ons', 'extensions', 'tools', 'features'],
        'template' => 'Your plugins are: {plugins_list}.',
        'data_source' => 'wp_rest'
      ],
      'users' => [
        'enabled' => 'on',
        'keywords' => ['admin', 'administrators', 'who can login'],
        'template' => 'You have {user_count} user{user_plural} with access to your site.',
        'data_source' => 'wp_rest'
      ],
      'updates' => [
        'enabled' => 'on',
        'keywords' => ['outdated', 'new version', 'upgrade', 'patches'],
        'template' => 'Updates pending — plugins: {plugin_updates}, themes: {theme_updates}, WordPress Core: {core_updates}.',
        'data_source' => 'wp_rest'
      ],
      'media' => [
        'enabled' => 'on',
        'keywords' => ['images', 'files', 'uploads', 'gallery'],
        'template' => 'Media information is available in your WordPress dashboard under Media.',
        'data_source' => 'custom'
      ]
    ],
    'security' => [
      'ssl' => [
        'enabled' => 'on',
        'keywords' => ['certificate', 'https', 'secure', 'encrypted'],
        'template' => '{ssl_status}',
        'data_source' => 'security'
      ],
      'firewall' => [
        'enabled' => 'on',
        'keywords' => ['protection', 'security', 'blocking', 'defense'],
        'template' => 'Firewall protection status is available in your security settings. Please check the Security tab in Visible Light for detailed firewall information.',
        'data_source' => 'security'
      ],
      'backup' => [
        'enabled' => 'on',
        'keywords' => ['backup', 'restore', 'recovery', 'safety'],
        'template' => 'Backup information is available in your security profile. Please check the Security tab in Visible Light for backup status and schedules.',
        'data_source' => 'security'
      ],
      'monitoring' => [
        'enabled' => 'on',
        'keywords' => ['scan', 'threats', 'vulnerabilities', 'alerts'],
        'template' => 'Security monitoring details are available in your security profile. Please check the Security tab in Visible Light for scan results and alerts.',
        'data_source' => 'security'
      ],
      'access' => [
        'enabled' => 'on',
        'keywords' => ['login', 'authentication', 'permissions', 'users'],
        'template' => 'You have {user_count} user{user_plural} with access to your site.',
        'data_source' => 'wp_rest'
      ],
      'compliance' => [
        'enabled' => 'on',
        'keywords' => ['hipaa', 'gdpr', 'standards', 'regulations'],
        'template' => 'Compliance information is available in your security profile. Please check the Security tab in Visible Light for compliance status and requirements.',
        'data_source' => 'security'
      ]
    ]
  ];
}

// Get current keyword mappings
function luna_get_keyword_mappings() {
  $custom = get_option('luna_keyword_mappings', []);
  
  // If we have custom data, return it directly
  if (!empty($custom)) {
    return $custom;
  }
  
  // Otherwise, return defaults
  return luna_get_default_keywords();
}

// Save keyword mappings
function luna_save_keyword_mappings($mappings) {
  // Debug: Log what's being processed
  error_log('Luna Keywords: Processing mappings: ' . print_r($mappings, true));
  
  // Process the new data structure
  $processed_mappings = array();
  
  foreach ($mappings as $category => $actions) {
    foreach ($actions as $action => $config) {
      // Skip if no keywords or empty config
      if (empty($config['keywords']) || !is_array($config['keywords'])) {
        continue;
      }
      
      $processed_config = array(
        'enabled' => $config['enabled'] ?? 'on',
        'keywords' => $config['keywords'] ?? array(),
        'data_source' => $config['data_source'] ?? 'custom',
        'response_type' => $config['response_type'] ?? 'simple'
      );
      
      // Only process active keywords for template processing
      if ($processed_config['enabled'] === 'on') {
        // Handle different data sources
        switch ($config['data_source']) {
          case 'wp_rest':
            $processed_config['wp_template'] = $config['wp_template'] ?? '';
            break;
          case 'security':
            $processed_config['security_template'] = $config['security_template'] ?? '';
            break;
          case 'custom':
          default:
            if ($config['response_type'] === 'advanced') {
              $processed_config['initial_response'] = $config['initial_response'] ?? '';
              $processed_config['branches'] = $config['branches'] ?? array();
            } else {
              $processed_config['template'] = $config['template'] ?? '';
            }
            break;
        }
      } else {
        // For disabled keywords, just store basic info without templates
        error_log("Luna Keywords: Storing disabled keyword - {$category}.{$action}");
      }
      
      $processed_mappings[$category][$action] = $processed_config;
    }
  }
  
  // Debug: Log what's being stored
  error_log('Luna Keywords: Final processed mappings: ' . print_r($processed_mappings, true));
  
  // Visual debug - show what's being processed
  echo '<div class="notice notice-info"><p><strong>DEBUG:</strong> Final processed mappings: ' . esc_html(print_r($processed_mappings, true)) . '</p></div>';
  
  update_option('luna_keyword_mappings', $processed_mappings);
  
  // Debug: Verify what was stored
  $stored = get_option('luna_keyword_mappings', array());
  error_log('Luna Keywords: Verified stored data: ' . print_r($stored, true));
  
  // Visual debug - show what was stored
  echo '<div class="notice notice-info"><p><strong>DEBUG:</strong> Verified stored data: ' . esc_html(print_r($stored, true)) . '</p></div>';
  
  // Send to Hub
  luna_sync_keywords_to_hub($processed_mappings);
}

// Sync keywords to Hub
function luna_sync_keywords_to_hub($mappings) {
  $license = luna_get_license();
  if (!$license) return;
  
  $response = wp_remote_post('https://visiblelight.ai/wp-json/luna_widget/v1/keywords/sync', [
    'timeout' => 10,
    'headers' => ['X-Luna-License' => $license, 'Content-Type' => 'application/json'],
    'body' => json_encode(['keywords' => $mappings])
  ]);
  
  if (is_wp_error($response)) {
    error_log('[Luna] Failed to sync keywords to Hub: ' . $response->get_error_message());
  }
}

// Sync analytics data to Hub
function luna_sync_analytics_to_hub($analytics_data) {
  $license = luna_get_license();
  if (!$license) return;

  $endpoint = luna_widget_hub_base() . '/wp-json/vl-hub/v1/sync-client-data';
  delete_transient('luna_ga4_metrics_' . md5($license));

  $response = wp_remote_post($endpoint, [
    'timeout' => 10,
    'headers' => ['X-Luna-License' => $license, 'Content-Type' => 'application/json'],
    'body' => json_encode([
      'license' => $license,
      'category' => 'analytics',
      'analytics_data' => $analytics_data
    ])
  ]);

  if (is_wp_error($response)) {
    error_log('[Luna] Failed to sync analytics to Hub: ' . $response->get_error_message());
  }
}

// Fetch data streams from Hub and extract GA4 metrics
function luna_fetch_hub_data_streams($license = null) {
  if (!$license) {
    $license = luna_get_license();
  }
  if (!$license) return null;

  $base = luna_widget_hub_base();
  $url  = add_query_arg(array('license' => $license), $base . '/wp-json/vl-hub/v1/data-streams');

  $response = wp_remote_get($url, array(
    'timeout' => 12,
    'headers' => array(
      'X-Luna-License' => $license,
      'X-Luna-Site'    => home_url('/'),
      'Accept'         => 'application/json',
    ),
    'sslverify' => true,
  ));

  if (is_wp_error($response)) {
    error_log('[Luna] Error fetching Hub data streams: ' . $response->get_error_message());
    return null;
  }

  $code = (int) wp_remote_retrieve_response_code($response);
  if ($code < 200 || $code >= 300) {
    error_log('[Luna] Hub data streams responded with HTTP ' . $code);
    return null;
  }

  $body = json_decode(wp_remote_retrieve_body($response), true);
  if (!is_array($body)) {
    error_log('[Luna] Hub data streams response was not valid JSON.');
    return null;
  }

  $streams_raw = array();
  if (isset($body['streams']) && is_array($body['streams'])) {
    $streams_raw = $body['streams'];
  } else {
    $streams_raw = $body;
  }

  $streams = array();
  foreach ($streams_raw as $stream_id => $stream_data) {
    if (is_array($stream_data)) {
      if (!isset($stream_data['_id'])) {
        $stream_data['_id'] = is_string($stream_id) ? $stream_id : null;
      }
      $streams[] = $stream_data;
    }
  }

  return $streams;
}

function luna_extract_ga4_metrics_from_streams($streams) {
  if (!is_array($streams)) return null;

  foreach ($streams as $stream) {
    if (!is_array($stream)) continue;

    if (!empty($stream['ga4_metrics']) && is_array($stream['ga4_metrics'])) {
      return array(
        'metrics'        => $stream['ga4_metrics'],
        'last_synced'    => isset($stream['ga4_last_synced']) ? $stream['ga4_last_synced'] : (isset($stream['last_updated']) ? $stream['last_updated'] : null),
        'date_range'     => isset($stream['ga4_date_range']) ? $stream['ga4_date_range'] : null,
        'source_url'     => isset($stream['source_url']) ? $stream['source_url'] : null,
        'property_id'    => isset($stream['ga4_property_id']) ? $stream['ga4_property_id'] : null,
        'measurement_id' => isset($stream['ga4_measurement_id']) ? $stream['ga4_measurement_id'] : null,
      );
    }
  }

  return null;
}

function luna_fetch_ga4_metrics_from_hub($license = null) {
  if (!$license) {
    $license = luna_get_license();
  }
  if (!$license) return null;

  $cache_key = 'luna_ga4_metrics_' . md5($license);
  $cached    = get_transient($cache_key);
  if (is_array($cached)) {
    return $cached;
  }

  $streams = luna_fetch_hub_data_streams($license);
  if (!$streams) {
    return null;
  }

  $ga4_info = luna_extract_ga4_metrics_from_streams($streams);
  if ($ga4_info) {
    set_transient($cache_key, $ga4_info, 5 * MINUTE_IN_SECONDS);
  }

  return $ga4_info;
}

// Sync security data to Hub
function luna_sync_security_to_hub($security_data) {
  $license = luna_get_license();
  if (!$license) return;

  $endpoint = luna_widget_hub_base() . '/wp-json/vl-hub/v1/sync-client-data';
  $response = wp_remote_post($endpoint, [
    'timeout' => 10,
    'headers' => ['X-Luna-License' => $license, 'Content-Type' => 'application/json'],
    'body' => json_encode([
      'license' => $license,
      'category' => 'security',
      'security_data' => $security_data
    ])
  ]);
  
  if (is_wp_error($response)) {
    error_log('[Luna] Failed to sync security to Hub: ' . $response->get_error_message());
  }
}

// Sync settings data to Hub
function luna_sync_settings_to_hub($settings_data) {
  $license = luna_get_license();
  if (!$license) return;

  $endpoint = luna_widget_hub_base() . '/wp-json/vl-hub/v1/sync-client-data';
  $response = wp_remote_post($endpoint, [
    'timeout' => 10,
    'headers' => ['X-Luna-License' => $license, 'Content-Type' => 'application/json'],
    'body' => json_encode([
      'license' => $license,
      'category' => 'infrastructure',
      'settings_data' => $settings_data
    ])
  ]);
  
  if (is_wp_error($response)) {
    error_log('[Luna] Failed to sync settings to Hub: ' . $response->get_error_message());
  }
}

// Get data from Hub for Luna Chat Widget
function luna_get_hub_data($category = null) {
  $license = luna_get_license();
  if (!$license) return null;
  
  // Get profile data from VL Hub which includes GA4 analytics
  $url = luna_widget_hub_base() . '/wp-json/vl-hub/v1/profile';
  $args = ['license' => $license];
  if ($category) {
    $args['category'] = $category;
  }
  
  $response = wp_remote_get(add_query_arg($args, $url), [
    'timeout' => 10,
    'headers' => ['X-Luna-License' => $license]
  ]);
  
  if (is_wp_error($response)) {
    error_log('[Luna] Failed to get data from Hub: ' . $response->get_error_message());
    return null;
  }
  
  $body = wp_remote_retrieve_body($response);
  $data = json_decode($body, true);
  
  // Extract GA4 metrics if available
  if (isset($data['ga4_metrics'])) {
    $data['analytics'] = $data['ga4_metrics'];
  }
  
  return $data;
}

/**
 * Fetch competitor analysis data from Hub.
 * 
 * @param string|null $license License key
 * @return array|null Competitor data or null on failure
 */
function luna_fetch_competitor_data($license = null) {
  if (!$license) {
    $license = luna_get_license();
  }
  if (!$license) return null;

  $hub_url = luna_widget_hub_base();
  $url = $hub_url . '/wp-json/vl-hub/v1/competitor-report';
  
  // First, get competitor URLs from settings
  $competitor_urls = array();
  $response = wp_remote_get($hub_url . '/wp-json/vl-hub/v1/profile?license=' . rawurlencode($license), array(
    'timeout' => 10,
    'headers' => array('X-Luna-License' => $license),
  ));

  if (!is_wp_error($response)) {
    $code = wp_remote_retrieve_response_code($response);
    if ($code === 200) {
      $body = wp_remote_retrieve_body($response);
      $profile = json_decode($body, true);
      if (is_array($profile)) {
        $profile = luna_hub_normalize_payload($profile);
      } else {
        $profile = null;
      }

      // Extract competitor URLs from enriched profile
      if (is_array($profile) && isset($profile['competitors']) && is_array($profile['competitors'])) {
        foreach ($profile['competitors'] as $competitor) {
          if (!empty($competitor['url'])) {
            $competitor_urls[] = $competitor['url'];
          } elseif (!empty($competitor['domain'])) {
            $competitor_urls[] = 'https://' . $competitor['domain'];
          }
        }
      }
    }
  }

  if (!empty($competitor_urls)) {
    $competitor_urls = array_values(array_unique(array_filter($competitor_urls)));
  }

  // Fetch reports for each competitor
  $competitor_reports = array();
  foreach ($competitor_urls as $competitor_url) {
    $report_url = add_query_arg(array(
      'license' => $license,
      'competitor_url' => $competitor_url,
    ), $url);

    $report_response = wp_remote_get($report_url, array(
      'timeout' => 10,
      'headers' => array('X-Luna-License' => $license),
    ));
    
    if (!is_wp_error($report_response)) {
      $report_code = wp_remote_retrieve_response_code($report_response);
      if ($report_code === 200) {
        $report_body = wp_remote_retrieve_body($report_response);
        $report_data = json_decode($report_body, true);
        
        if (!is_array($report_data)) {
          continue;
        }

        $report_payload = null;
        if (isset($report_data['success']) && $report_data['success'] && isset($report_data['report']) && is_array($report_data['report'])) {
          $report_payload = $report_data['report'];
        } elseif (isset($report_data['ok']) && $report_data['ok'] && isset($report_data['data']) && is_array($report_data['data'])) {
          $report_payload = $report_data['data'];
        }

        if ($report_payload === null) {
          continue;
        }

        $domain = parse_url($competitor_url, PHP_URL_HOST);
        if (!$domain) {
          $domain = $competitor_url;
        }

        $competitor_reports[] = array(
          'url' => $competitor_url,
          'domain' => $domain,
          'report' => $report_payload,
          'last_scanned' => $report_data['last_scanned'] ?? null,
          'status' => $report_data['status'] ?? null,
        );
      }
    }
  }
  
  return !empty($competitor_reports) ? array(
    'competitors' => $competitor_urls,
    'reports' => $competitor_reports,
  ) : null;
}

/**
 * Fetch VLDR (Domain Ranking) data from Hub with caching.
 * 
 * @param string $domain Domain to check
 * @param string|null $license License key
 * @return array|null VLDR data or null on failure
 */
function luna_fetch_vldr_data($domain, $license = null) {
  if (!$license) {
    $license = luna_get_license();
  }
  if (!$license || empty($domain)) return null;

  // Clean domain
  $domain = preg_replace('/^https?:\/\//', '', $domain);
  $domain = preg_replace('/^www\./', '', $domain);
  $domain = rtrim($domain, '/');
  $domain = strtolower($domain);

  // Cache key with 30-minute TTL
  $cache_key = 'luna_vldr_' . md5($license . '|' . $domain);
  $cached = get_transient($cache_key);
  if ($cached !== false && is_array($cached)) {
    return $cached;
  }

  // Fetch from Hub REST API
  $hub_url = luna_widget_hub_base();
  $url = $hub_url . '/wp-json/vl-hub/v1/vldr?license=' . rawurlencode($license) . '&domain=' . rawurlencode($domain);

  $response = wp_remote_get($url, array(
    'timeout' => 15,
    'sslverify' => true,
    'headers' => array(
      'Accept' => 'application/json',
      'X-Luna-License' => $license,
    ),
  ));

  if (is_wp_error($response)) {
    error_log('[Luna VLDR] Error fetching from Hub: ' . $response->get_error_message());
    return null;
  }

  $code = wp_remote_retrieve_response_code($response);
  if ($code !== 200) {
    error_log('[Luna VLDR] HTTP ' . $code . ' from Hub for domain: ' . $domain);
    return null;
  }

  $body = wp_remote_retrieve_body($response);
  $data = json_decode($body, true);

  if (!is_array($data)) {
    error_log('[Luna VLDR] Invalid JSON response from Hub');
    return null;
  }

  // Check for success response
  if (!empty($data['ok']) && !empty($data['data']) && is_array($data['data'])) {
    $vldr_data = $data['data'];
    
    // Cache for 30 minutes
    set_transient($cache_key, $vldr_data, 30 * MINUTE_IN_SECONDS);
    
    return $vldr_data;
  }

  // Check for direct data structure (if no wrapper)
  if (!empty($data['domain']) && isset($data['vldr_score'])) {
    set_transient($cache_key, $data, 30 * MINUTE_IN_SECONDS);
    return $data;
  }

  return null;
}

// Get interactions count for Luna Widget
function luna_get_interactions_count() {
  $license = luna_get_license();
  if (!$license) return 0;
  
  // Get interactions count from stored data
  $interactions_data = get_option('luna_interactions_' . $license, array());
  return isset($interactions_data['total_interactions']) ? (int)$interactions_data['total_interactions'] : 0;
}

// Get chat transcript for Luna Widget
function luna_get_chat_transcript($license_key) {
  if (empty($license_key)) return array();
  
  // Get chat transcript from stored data
  $transcript_data = get_option('luna_chat_transcript_' . $license_key, array());
  return $transcript_data;
}

// Calculate SEO score for posts and pages
function luna_calculate_seo_score($post_id) {
  $score = 0;
  $max_score = 100;
  
  // Title (20 points)
  $title = get_the_title($post_id);
  if (!empty($title)) {
    $score += 20;
    if (strlen($title) >= 30 && strlen($title) <= 60) {
      $score += 5; // Bonus for optimal length
    }
  }
  
  // Content (20 points)
  $content = get_post_field('post_content', $post_id);
  if (!empty($content)) {
    $score += 20;
    if (str_word_count($content) >= 300) {
      $score += 10; // Bonus for substantial content
    }
  }
  
  // Excerpt (10 points)
  $excerpt = get_the_excerpt($post_id);
  if (!empty($excerpt)) {
    $score += 10;
  }
  
  // Featured image (10 points)
  if (has_post_thumbnail($post_id)) {
    $score += 10;
  }
  
  // Categories/Tags (10 points)
  $categories = wp_get_post_terms($post_id, 'category');
  $tags = wp_get_post_terms($post_id, 'post_tag');
  if (!empty($categories) || !empty($tags)) {
    $score += 10;
  }
  
  // Meta description (10 points)
  $meta_description = get_post_meta($post_id, '_yoast_wpseo_metadesc', true);
  if (empty($meta_description)) {
    $meta_description = get_post_meta($post_id, '_aioseo_description', true);
  }
  if (!empty($meta_description)) {
    $score += 10;
  }
  
  // Focus keyword (10 points)
  $focus_keyword = get_post_meta($post_id, '_yoast_wpseo_focuskw', true);
  if (empty($focus_keyword)) {
    $focus_keyword = get_post_meta($post_id, '_aioseo_keywords', true);
  }
  if (!empty($focus_keyword)) {
    $score += 10;
  }
  
  // Internal links (5 points)
  if (strpos($content, '<a href="' . home_url()) !== false) {
    $score += 5;
  }
  
  // External links (5 points)
  if (preg_match('/<a href="(?!' . preg_quote(home_url(), '/') . ')/', $content)) {
    $score += 5;
  }
  
  return min($score, $max_score);
}

// Track keyword usage and performance
function luna_track_keyword_usage($keyword_match, $response_success = true) {
  $usage_stats = get_option('luna_keyword_usage', []);
  
  $key = $keyword_match['category'] . '.' . $keyword_match['action'];
  
  if (!isset($usage_stats[$key])) {
    $usage_stats[$key] = [
      'total_uses' => 0,
      'successful_uses' => 0,
      'failed_uses' => 0,
      'last_used' => current_time('mysql'),
      'keywords' => $keyword_match['matched_term']
    ];
  }
  
  $usage_stats[$key]['total_uses']++;
  $usage_stats[$key]['last_used'] = current_time('mysql');
  
  if ($response_success) {
    $usage_stats[$key]['successful_uses']++;
  } else {
    $usage_stats[$key]['failed_uses']++;
  }
  
  update_option('luna_keyword_usage', $usage_stats);
}

// Get keyword performance statistics
function luna_get_keyword_performance() {
  $usage_stats = get_option('luna_keyword_usage', []);
  $performance = [];
  
  foreach ($usage_stats as $key => $stats) {
    $success_rate = $stats['total_uses'] > 0 ? ($stats['successful_uses'] / $stats['total_uses']) * 100 : 0;
    
    $performance[$key] = [
      'total_uses' => $stats['total_uses'],
      'success_rate' => round($success_rate, 1),
      'last_used' => $stats['last_used'],
      'keywords' => $stats['keywords']
    ];
  }
  
  // Sort by total uses (most popular first)
  uasort($performance, function($a, $b) {
    return $b['total_uses'] - $a['total_uses'];
  });
  
  return $performance;
}

// Check if user input matches any keywords
function luna_check_keyword_mappings($user_input) {
  $mappings = luna_get_keyword_mappings();
  $lc_input = strtolower(trim($user_input));
  
  // Debug: Log what we're checking
  error_log('Luna Keywords: Checking input: "' . $lc_input . '"');
  
  foreach ($mappings as $category => $keywords) {
    foreach ($keywords as $action => $config) {
      // Skip disabled keywords
      if (isset($config['enabled']) && $config['enabled'] !== 'on') {
        continue;
      }
      
      // Handle both old format (array of terms) and new format (config object)
      $terms = is_array($config) && isset($config['keywords']) ? $config['keywords'] : $config;
      
      if (!is_array($terms)) {
        continue;
      }
      
      foreach ($terms as $term) {
        $lc_term = strtolower(trim($term));
        if (empty($lc_term)) continue;
        
        // Use word boundary matching for more precise matching
        if (preg_match('/\b' . preg_quote($lc_term, '/') . '\b/', $lc_input)) {
          error_log('Luna Keywords: Matched term "' . $lc_term . '" for ' . $category . '.' . $action);
          return [
            'category' => $category,
            'action' => $action,
            'matched_term' => $term,
            'config' => is_array($config) && isset($config['template']) ? $config : null
          ];
        }
      }
    }
  }
  
  error_log('Luna Keywords: No keyword matches found');
  return null;
}

// Handle keyword-based responses using templates
function luna_handle_keyword_response($keyword_match, $facts) {
  $category = $keyword_match['category'];
  $action = $keyword_match['action'];
  $matched_term = $keyword_match['matched_term'];
  $config = $keyword_match['config'];
  
  // If we have a template config, use it
  if ($config) {
    $data_source = $config['data_source'] ?? 'custom';
    $response_type = $config['response_type'] ?? 'simple';
    
    switch ($data_source) {
      case 'wp_rest':
        return luna_process_response_template($config['wp_template'] ?? '', 'wp_rest', $facts);
      case 'security':
        return luna_process_response_template($config['security_template'] ?? '', 'security', $facts);
      case 'custom':
      default:
        if ($response_type === 'advanced') {
          // For advanced responses, we'll return the initial response
          // The branching logic would be handled in a more complex conversation flow
          return luna_process_response_template($config['initial_response'] ?? '', 'custom', $facts);
        } else {
          return luna_process_response_template($config['template'] ?? '', 'custom', $facts);
        }
    }
  }
  
  // Fallback to old system for backward compatibility
  switch ($category) {
    case 'business':
      return luna_handle_business_keyword($action, $facts);
      
    case 'wp_rest':
      return luna_handle_wp_rest_keyword($action, $facts);
      
    case 'security':
      return luna_handle_security_keyword($action, $facts);
      
    default:
      return null;
  }
}

// Process response templates with dynamic data
function luna_process_response_template($template, $data_source, $facts) {
  $response = $template;
  
  // Replace template variables based on data source
  switch ($data_source) {
    case 'wp_rest':
      $response = luna_replace_wp_rest_variables($response, $facts);
      break;
      
    case 'security':
      $response = luna_replace_security_variables($response, $facts);
      break;
      
    case 'custom':
      $response = luna_replace_custom_shortcodes($response, $facts);
      break;
  }
  
  return $response;
}

// Replace WP REST API variables in templates
function luna_replace_wp_rest_variables($template, $facts) {
  $replacements = [];
  
  // Pages list
  if (strpos($template, '{pages_list}') !== false) {
    if (isset($facts['pages']) && is_array($facts['pages']) && !empty($facts['pages'])) {
      $page_names = array();
      foreach ($facts['pages'] as $page) {
        $status = isset($page['status']) ? $page['status'] : 'published';
        $page_names[] = $page['title'] . " (" . $status . ")";
      }
      $replacements['{pages_list}'] = implode(", ", $page_names);
    } else {
      $replacements['{pages_list}'] = "No pages found";
    }
  }
  
  // Posts list
  if (strpos($template, '{posts_list}') !== false) {
    if (isset($facts['posts']) && is_array($facts['posts']) && !empty($facts['posts'])) {
      $post_names = array();
      foreach ($facts['posts'] as $post) {
        $status = isset($post['status']) ? $post['status'] : 'published';
        $post_names[] = $post['title'] . " (" . $status . ")";
      }
      $replacements['{posts_list}'] = implode(", ", $post_names);
    } else {
      $replacements['{posts_list}'] = "No posts found";
    }
  }
  
  // Themes list
  if (strpos($template, '{themes_list}') !== false) {
    if (isset($facts['themes']) && is_array($facts['themes']) && !empty($facts['themes'])) {
      $active_themes = array();
      $inactive_themes = array();
      foreach ($facts['themes'] as $theme) {
        if (isset($theme['is_active']) && $theme['is_active']) {
          $active_themes[] = $theme['name'] . " (Active)";
        } else {
          $inactive_themes[] = $theme['name'] . " (Inactive)";
        }
      }
      $all_themes = array_merge($active_themes, $inactive_themes);
      $replacements['{themes_list}'] = implode(", ", $all_themes);
    } else {
      $replacements['{themes_list}'] = "No themes found";
    }
  }
  
  // Plugins list
  if (strpos($template, '{plugins_list}') !== false) {
    if (isset($facts['plugins']) && is_array($facts['plugins']) && !empty($facts['plugins'])) {
      $plugin_names = array();
      foreach ($facts['plugins'] as $plugin) {
        $status = isset($plugin['active']) && $plugin['active'] ? 'Active' : 'Inactive';
        $plugin_names[] = $plugin['name'] . " (" . $status . ")";
      }
      $replacements['{plugins_list}'] = implode(", ", $plugin_names);
    } else {
      $replacements['{plugins_list}'] = "No plugins found";
    }
  }
  
  // User count
  if (strpos($template, '{user_count}') !== false) {
    $user_count = isset($facts['users']) && is_array($facts['users']) ? count($facts['users']) : 0;
    $replacements['{user_count}'] = $user_count;
    $replacements['{user_plural}'] = $user_count === 1 ? '' : 's';
  }
  
  // Update counts
  if (strpos($template, '{plugin_updates}') !== false) {
    $replacements['{plugin_updates}'] = (int)($facts['updates']['plugins'] ?? 0);
  }
  if (strpos($template, '{theme_updates}') !== false) {
    $replacements['{theme_updates}'] = (int)($facts['updates']['themes'] ?? 0);
  }
  if (strpos($template, '{core_updates}') !== false) {
    $replacements['{core_updates}'] = (int)($facts['updates']['core'] ?? 0);
  }
  
  // Apply all replacements
  foreach ($replacements as $placeholder => $value) {
    $template = str_replace($placeholder, $value, $template);
  }
  
  return $template;
}

// Replace security variables in templates
function luna_replace_security_variables($template, $facts) {
  if (strpos($template, '{ssl_status}') !== false) {
    if (!empty($facts['tls']['valid'])) {
      $extras = array();
      if (!empty($facts['tls']['issuer'])) $extras[] = "issuer: " . $facts['tls']['issuer'];
      if (!empty($facts['tls']['expires'])) $extras[] = "expires: " . $facts['tls']['expires'];
      $ssl_status = "Yes—TLS/SSL is active for " . $facts['site_url'] . ($extras ? " (" . implode(', ', $extras) . ")." : ".");
    } else {
      $ssl_status = "Hub shows TLS/SSL is not confirmed active for " . $facts['site_url'] . ". Please review the Security tab in Visible Light.";
    }
    $template = str_replace('{ssl_status}', $ssl_status, $template);
  }
  
  return $template;
}

// Replace custom shortcodes in templates
function luna_replace_custom_shortcodes($template, $facts) {
  $replacements = [];
  
  // Contact page link
  if (strpos($template, '[contact_page]') !== false) {
    $contact_url = get_permalink(get_page_by_path('contact'));
    if (!$contact_url) {
      $contact_url = home_url('/contact/');
    }
    $replacements['[contact_page]'] = '<a href="' . esc_url($contact_url) . '" target="_blank">Contact Page</a>';
  }
  
  // Booking link
  if (strpos($template, '[booking_link]') !== false) {
    $booking_url = get_permalink(get_page_by_path('book'));
    if (!$booking_url) {
      $booking_url = home_url('/book/');
    }
    $replacements['[booking_link]'] = '<a href="' . esc_url($booking_url) . '" target="_blank">Book Appointment</a>';
  }
  
  // Phone number
  if (strpos($template, '[phone_number]') !== false) {
    $phone = get_option('luna_business_phone', '(555) 123-4567');
    $replacements['[phone_number]'] = '<a href="tel:' . esc_attr($phone) . '">' . esc_html($phone) . '</a>';
  }
  
  // Email link
  if (strpos($template, '[email_link]') !== false) {
    $email = get_option('luna_business_email', 'info@example.com');
    $replacements['[email_link]'] = '<a href="mailto:' . esc_attr($email) . '">' . esc_html($email) . '</a>';
  }
  
  // Site URL
  if (strpos($template, '[site_url]') !== false) {
    $replacements['[site_url]'] = '<a href="' . esc_url(home_url()) . '" target="_blank">' . esc_html(get_bloginfo('name')) . '</a>';
  }
  
  // Business name
  if (strpos($template, '[business_name]') !== false) {
    $business_name = get_option('luna_business_name', get_bloginfo('name'));
    $replacements['[business_name]'] = esc_html($business_name);
  }
  
  return str_replace(array_keys($replacements), array_values($replacements), $template);
}

// Handle business-specific keywords
function luna_handle_business_keyword($action, $facts) {
  switch ($action) {
    case 'appointment':
      return "To schedule an appointment, please call our office or use our online booking system. You can find our contact information on our website.";
      
    case 'contact':
      return "You can reach us through our contact page or by calling our main office number. Our contact information is available on our website.";
      
    case 'hours':
      return "Our business hours are typically Monday through Friday, 9 AM to 5 PM. Please check our website for the most current hours and holiday schedules.";
      
    case 'location':
      return "You can find our address and directions on our website's contact page. We're located in a convenient area with parking available.";
      
    case 'services':
      return "We offer a comprehensive range of services. Please visit our services page on our website for detailed information about what we provide.";
      
    case 'providers':
      return "Our team of experienced providers is dedicated to your care. You can learn more about our staff on our website's team page.";
      
    case 'insurance':
      return "We accept most major insurance plans. Please contact our billing department to verify your coverage and discuss payment options.";
      
    case 'forms':
      return "You can download patient forms from our website or pick them up at our office. Please complete them before your visit to save time.";
      
    default:
      return null;
  }
}

// Handle WP REST API keywords
function luna_handle_wp_rest_keyword($action, $facts) {
  switch ($action) {
    case 'pages':
      if (isset($facts['pages']) && is_array($facts['pages']) && !empty($facts['pages'])) {
        $page_names = array();
        foreach ($facts['pages'] as $page) {
          $status = isset($page['status']) ? $page['status'] : 'published';
          $page_names[] = $page['title'] . " (" . $status . ")";
        }
        return "Your pages are: " . implode(", ", $page_names) . ".";
      }
      return "I don't see any pages in your site data.";
      
    case 'posts':
      if (isset($facts['posts']) && is_array($facts['posts']) && !empty($facts['posts'])) {
        $post_names = array();
        foreach ($facts['posts'] as $post) {
          $status = isset($post['status']) ? $post['status'] : 'published';
          $post_names[] = $post['title'] . " (" . $status . ")";
        }
        return "Your posts are: " . implode(", ", $post_names) . ".";
      }
      return "I don't see any posts in your site data.";
      
    case 'themes':
      if (isset($facts['themes']) && is_array($facts['themes']) && !empty($facts['themes'])) {
        $active_themes = array();
        $inactive_themes = array();
        foreach ($facts['themes'] as $theme) {
          if (isset($theme['is_active']) && $theme['is_active']) {
            $active_themes[] = $theme['name'] . " (Active)";
          } else {
            $inactive_themes[] = $theme['name'] . " (Inactive)";
          }
        }
        $all_themes = array_merge($active_themes, $inactive_themes);
        return "Your themes are: " . implode(", ", $all_themes) . ".";
      }
      return "I don't see any themes in your site data.";
      
    case 'plugins':
      if (isset($facts['plugins']) && is_array($facts['plugins']) && !empty($facts['plugins'])) {
        $plugin_names = array();
        foreach ($facts['plugins'] as $plugin) {
          $status = isset($plugin['active']) && $plugin['active'] ? 'Active' : 'Inactive';
          $plugin_names[] = $plugin['name'] . " (" . $status . ")";
        }
        return "Your plugins are: " . implode(", ", $plugin_names) . ".";
      }
      return "I don't see any plugins in your site data.";
      
    case 'updates':
      $pu = (int)($facts['updates']['plugins'] ?? 0);
      $tu = (int)($facts['updates']['themes'] ?? 0);
      $cu = (int)($facts['updates']['core'] ?? 0);
      return "Updates pending — plugins: " . $pu . ", themes: " . $tu . ", WordPress Core: " . $cu . ".";
      
    default:
      return null;
  }
}

// Handle security keywords
function luna_handle_security_keyword($action, $facts) {
  switch ($action) {
    case 'ssl':
      if (!empty($facts['tls']['valid'])) {
        $extras = array();
        if (!empty($facts['tls']['issuer'])) $extras[] = "issuer: " . $facts['tls']['issuer'];
        if (!empty($facts['tls']['expires'])) $extras[] = "expires: " . $facts['tls']['expires'];
        return "Yes—TLS/SSL is active for " . $facts['site_url'] . ($extras ? " (" . implode(', ', $extras) . ")." : ".");
      }
      return "Hub shows TLS/SSL is not confirmed active for " . $facts['site_url'] . ". Please review the Security tab in Visible Light.";
      
    case 'firewall':
      return "Firewall protection status is available in your security settings. Please check the Security tab in Visible Light for detailed firewall information.";
      
    case 'backup':
      return "Backup information is available in your security profile. Please check the Security tab in Visible Light for backup status and schedules.";
      
    case 'monitoring':
      return "Security monitoring details are available in your security profile. Please check the Security tab in Visible Light for scan results and alerts.";
      
    case 'access':
      if (isset($facts['users']) && is_array($facts['users']) && !empty($facts['users'])) {
        $user_count = count($facts['users']);
        return "You have " . $user_count . " user" . ($user_count === 1 ? '' : 's') . " with access to your site.";
      }
      return "User access information is available in your security profile.";
      
    case 'compliance':
      return "Compliance information is available in your security profile. Please check the Security tab in Visible Light for compliance status and requirements.";
      
    default:
      return null;
  }
}

// Keywords admin page with enhanced template system
function luna_widget_keywords_admin_page() {
  if (isset($_POST['save_keywords'])) {
    check_admin_referer('luna_keywords_nonce');
    
    // Debug: Show what's being submitted (temporarily disabled)
    // echo '<div style="background: #e7f3ff; padding: 10px; margin: 10px 0; border: 1px solid #0073aa;">';
    // echo '<h4>Debug: POST Data Received</h4>';
    // echo '<pre>' . print_r($_POST, true) . '</pre>';
    // echo '</div>';
    
    // Process the form data properly
    if (isset($_POST['keywords'])) {
      $processed_keywords = array();
      
      foreach ($_POST['keywords'] as $category => $actions) {
        $processed_keywords[$category] = array();
        
        foreach ($actions as $action => $config) {
          // Skip if no keywords provided
          if (empty($config['keywords'])) {
            continue;
          }
          
          // Process keywords - split by comma and trim
          $keywords_array = array_map('trim', explode(',', $config['keywords']));
          $keywords_array = array_filter($keywords_array); // Remove empty values
          
          if (empty($keywords_array)) {
            continue;
          }
          
          $processed_config = array(
            'enabled' => isset($config['enabled']) ? 'on' : 'off',
            'keywords' => $keywords_array,
            'template' => sanitize_textarea_field($config['template'] ?? ''),
            'data_source' => sanitize_text_field($config['data_source'] ?? 'custom'),
            'response_type' => sanitize_text_field($config['response_type'] ?? 'simple')
          );
          
          // Add additional fields if they exist
          if (isset($config['wp_template'])) {
            $processed_config['wp_template'] = sanitize_textarea_field($config['wp_template']);
          }
          if (isset($config['security_template'])) {
            $processed_config['security_template'] = sanitize_textarea_field($config['security_template']);
          }
          if (isset($config['initial_response'])) {
            $processed_config['initial_response'] = sanitize_textarea_field($config['initial_response']);
          }
          if (isset($config['branches'])) {
            $processed_config['branches'] = $config['branches'];
          }
          
          $processed_keywords[$category][$action] = $processed_config;
        }
      }
      
      // Save the processed keywords
      update_option('luna_keyword_mappings', $processed_keywords);
      
      // Debug: Show what was saved (temporarily disabled)
      // echo '<div style="background: #d4edda; padding: 10px; margin: 10px 0; border: 1px solid #c3e6cb;">';
      // echo '<h4>Debug: Processed and Saved Keywords</h4>';
      // echo '<pre>' . print_r($processed_keywords, true) . '</pre>';
      // echo '</div>';
      
      // Sync to Hub
      luna_sync_keywords_to_hub();
      
      echo '<div class="notice notice-success"><p>Keywords saved and synced to Hub!</p></div>';
    }
  }
  
  // Load mappings for display - merge with defaults to show all keywords
  $saved_mappings = get_option('luna_keyword_mappings', []);
  $default_mappings = luna_get_default_keywords();
  $mappings = [];
  
  // Start with defaults
  foreach ($default_mappings as $category => $keywords) {
    $mappings[$category] = [];
    foreach ($keywords as $action => $default_config) {
      // Use saved data if it exists, otherwise use default
      if (isset($saved_mappings[$category][$action])) {
        $mappings[$category][$action] = $saved_mappings[$category][$action];
      } else {
        $mappings[$category][$action] = $default_config;
      }
    }
  }
  
  // Add any custom keywords that aren't in defaults
  foreach ($saved_mappings as $category => $keywords) {
    if (!isset($mappings[$category])) {
      $mappings[$category] = [];
    }
    foreach ($keywords as $action => $config) {
      if (!isset($mappings[$category][$action])) {
        $mappings[$category][$action] = $config;
      }
    }
  }
  
  // Debug: Show what we're working with (temporarily disabled)
  // echo '<div style="background: #f0f0f0; padding: 10px; margin: 10px 0; border: 1px solid #ccc;">';
  // echo '<h4>Debug: Current Mappings</h4>';
  // echo '<pre>' . print_r($mappings, true) . '</pre>';
  // echo '</div>';
  ?>
    <div class="wrap">
      <h1>Luna Chat Keywords & Templates</h1>
      <p>Configure keyword mappings and response templates to help Luna understand your business terminology and respond more accurately.</p>
      
      <div style="margin: 20px 0;">
        <button type="button" id="add-new-keyword" class="button button-primary">+ Add New Keyword</button>
        <button type="button" id="add-new-category" class="button">+ Add New Category</button>
        <button type="button" id="manage-keywords" class="button">Manage Existing Keywords</button>
      </div>
      
      <!-- Modal for adding new keyword -->
      <div id="keyword-modal" class="luna-modal" style="display: none;">
        <div class="luna-modal-content">
          <div class="luna-modal-header">
            <h2>Add New Keyword</h2>
            <span class="luna-modal-close">&times;</span>
          </div>
          <div class="luna-modal-body">
            <table class="form-table">
              <tr>
                <th scope="row">Category</th>
                <td>
                  <select id="new-keyword-category" class="regular-text">
                    <option value="business">Business</option>
                    <option value="wp_rest">WordPress Data</option>
                    <option value="security">Security</option>
                    <option value="custom">Custom</option>
                  </select>
                  <p class="description">Select the category for this keyword</p>
                </td>
              </tr>
              <tr>
                <th scope="row">Keyword Name</th>
                <td>
                  <input type="text" id="new-keyword-name" class="regular-text" placeholder="e.g., pricing, hours, support">
                  <p class="description">Enter a unique name for this keyword</p>
                </td>
              </tr>
              <tr>
                <th scope="row">Keywords</th>
                <td>
                  <input type="text" id="new-keyword-terms" class="regular-text" placeholder="Enter keywords separated by commas">
                  <p class="description">Words or phrases that will trigger this response</p>
                </td>
              </tr>
              <tr>
                <th scope="row">Data Source</th>
                <td>
                  <select id="new-keyword-data-source" class="regular-text">
                    <option value="custom">Custom Response</option>
                    <option value="wp_rest">WordPress Data</option>
                    <option value="security">Security Data</option>
                  </select>
                </td>
              </tr>
              <tr>
                <th scope="row">Response Template</th>
                <td>
                  <textarea id="new-keyword-template" class="large-text" rows="3" placeholder="Enter your response template..."></textarea>
                </td>
              </tr>
            </table>
          </div>
          <div class="luna-modal-footer">
            <button type="button" id="save-new-keyword" class="button button-primary">Add Keyword</button>
            <button type="button" id="cancel-new-keyword" class="button">Cancel</button>
          </div>
        </div>
      </div>
      
      <!-- Modal for adding new category -->
      <div id="category-modal" class="luna-modal" style="display: none;">
        <div class="luna-modal-content">
          <div class="luna-modal-header">
            <h2>Add New Category</h2>
            <span class="luna-modal-close">&times;</span>
          </div>
          <div class="luna-modal-body">
            <table class="form-table">
              <tr>
                <th scope="row">Category Name</th>
                <td>
                  <input type="text" id="new-category-name" class="regular-text" placeholder="e.g., products, services, support">
                  <p class="description">Enter a name for the new category</p>
                </td>
              </tr>
              <tr>
                <th scope="row">Description</th>
                <td>
                  <input type="text" id="new-category-description" class="regular-text" placeholder="Brief description of this category">
                  <p class="description">Optional description for this category</p>
                </td>
              </tr>
            </table>
          </div>
          <div class="luna-modal-footer">
            <button type="button" id="save-new-category" class="button button-primary">Add Category</button>
            <button type="button" id="cancel-new-category" class="button">Cancel</button>
          </div>
        </div>
      </div>
      
      <!-- Modal for managing existing keywords -->
      <div id="manage-modal" class="luna-modal" style="display: none;">
        <div class="luna-modal-content" style="width: 80%; max-width: 800px;">
          <div class="luna-modal-header">
            <h2>Manage Existing Keywords</h2>
            <span class="luna-modal-close">&times;</span>
          </div>
          <div class="luna-modal-body">
            <p>Move existing keywords to different categories:</p>
            <div id="keyword-management-list"></div>
          </div>
          <div class="luna-modal-footer">
            <button type="button" id="save-keyword-changes" class="button button-primary">Save Changes</button>
            <button type="button" id="cancel-keyword-changes" class="button">Cancel</button>
          </div>
        </div>
      </div>
    
    <div class="luna-keywords-help">
      <h3>Template Variables</h3>
      <p>Use these variables in your response templates:</p>
      <ul>
        <li><code>{pages_list}</code> - List of pages with status</li>
        <li><code>{posts_list}</code> - List of posts with status</li>
        <li><code>{themes_list}</code> - List of themes with active status</li>
        <li><code>{plugins_list}</code> - List of plugins with active status</li>
        <li><code>{user_count}</code> - Number of users</li>
        <li><code>{user_plural}</code> - "s" if multiple users, "" if single</li>
        <li><code>{plugin_updates}</code> - Number of plugin updates available</li>
        <li><code>{theme_updates}</code> - Number of theme updates available</li>
        <li><code>{core_updates}</code> - Number of WordPress core updates available</li>
        <li><code>{ssl_status}</code> - SSL certificate status</li>
      </ul>
    </div>
    
    <form method="post">
      <?php wp_nonce_field('luna_keywords_nonce'); ?>
      
      <div class="luna-keywords-container">
        <?php foreach ($mappings as $category => $keywords): ?>
          <div class="luna-keyword-category">
            <h3><?php echo ucfirst($category); ?> Keywords</h3>
            <table class="form-table">
              <?php foreach ($keywords as $action => $config): ?>
                <?php 
                // Handle both old format (array of terms) and new format (config object)
                $terms = is_array($config) && isset($config['keywords']) ? $config['keywords'] : $config;
                $template = is_array($config) && isset($config['template']) ? $config['template'] : '';
                $data_source = is_array($config) && isset($config['data_source']) ? $config['data_source'] : 'custom';
                $enabled = is_array($config) && isset($config['enabled']) ? $config['enabled'] : 'off';
                
                // Debug: Show enabled state for this keyword (only in debug mode)
                if (WP_DEBUG) {
                  echo "<!-- DEBUG: {$category}.{$action} - enabled: {$enabled} -->";
                }
                ?>
                <tr>
                  <th scope="row"><?php echo ucfirst($action); ?></th>
                  <td>
                    <div class="luna-keyword-config">
                      <div class="luna-keyword-field">
                        <label>
                          <input type="checkbox" name="keywords[<?php echo $category; ?>][<?php echo $action; ?>][enabled]" 
                                 value="on" <?php checked('on', $enabled); ?> 
                                 onchange="luna_toggle_keyword('<?php echo $category; ?>', '<?php echo $action; ?>')">
                          Enable this keyword
                        </label>
                      </div>
                      
                      <div class="luna-keyword-field">
                        <label>Keywords:</label>
                        <input type="text" name="keywords[<?php echo $category; ?>][<?php echo $action; ?>][terms]" 
                               value="<?php echo esc_attr(is_array($terms) ? implode(', ', $terms) : $terms); ?>" 
                               class="regular-text" 
                               placeholder="Enter keywords separated by commas">
                      </div>
                      
                      <div class="luna-keyword-field">
                        <label>Data Source:</label>
                        <select name="keywords[<?php echo $category; ?>][<?php echo $action; ?>][data_source]" 
                                onchange="luna_toggle_data_source_options(this, '<?php echo $category; ?>', '<?php echo $action; ?>')">
                          <option value="custom" <?php selected($data_source, 'custom'); ?>>Custom Response</option>
                          <option value="wp_rest" <?php selected($data_source, 'wp_rest'); ?>>WordPress Data</option>
                          <option value="security" <?php selected($data_source, 'security'); ?>>Security Data</option>
                        </select>
                      </div>
                      
                      <!-- WordPress Data Options -->
                      <div class="luna-data-source-options luna-wp-rest-options" 
                           style="display: <?php echo $data_source === 'wp_rest' ? 'block' : 'none'; ?>;">
                        <div class="luna-keyword-field">
                          <label>WordPress Data Response:</label>
                          <textarea name="keywords[<?php echo $category; ?>][<?php echo $action; ?>][wp_template]" 
                                    class="large-text" rows="3" 
                                    placeholder="Use variables: {pages_list}, {posts_list}, {themes_list}, {plugins_list}, {user_count}, {user_plural}, {plugin_updates}, {theme_updates}, {core_updates}"><?php echo esc_textarea($config['wp_template'] ?? ''); ?></textarea>
                          <p class="description">
                            <strong>Available Variables:</strong><br>
                            <code>{pages_list}</code> - List of pages with status<br>
                            <code>{posts_list}</code> - List of posts with status<br>
                            <code>{themes_list}</code> - List of themes with active status<br>
                            <code>{plugins_list}</code> - List of plugins with active status<br>
                            <code>{user_count}</code> - Number of users<br>
                            <code>{user_plural}</code> - "s" if multiple users, "" if single<br>
                            <code>{plugin_updates}</code> - Number of plugin updates available<br>
                            <code>{theme_updates}</code> - Number of theme updates available<br>
                            <code>{core_updates}</code> - Number of WordPress core updates available
                          </p>
                        </div>
                        <div class="luna-keyword-field">
                          <label>Shortcode Generator:</label>
                          <select onchange="luna_insert_shortcode(this.value, 'keywords[<?php echo $category; ?>][<?php echo $action; ?>][wp_template]')">
                            <option value="">Select a shortcode to insert...</option>
                            <option value="{pages_list}">Pages List</option>
                            <option value="{posts_list}">Posts List</option>
                            <option value="{themes_list}">Themes List</option>
                            <option value="{plugins_list}">Plugins List</option>
                            <option value="{user_count}">User Count</option>
                            <option value="{plugin_updates}">Plugin Updates</option>
                            <option value="{theme_updates}">Theme Updates</option>
                            <option value="{core_updates}">Core Updates</option>
                          </select>
                        </div>
                      </div>
                      
                      <!-- Security Data Options -->
                      <div class="luna-data-source-options luna-security-options" 
                           style="display: <?php echo $data_source === 'security' ? 'block' : 'none'; ?>;">
                        <div class="luna-keyword-field">
                          <label>Security Data Response:</label>
                          <textarea name="keywords[<?php echo $category; ?>][<?php echo $action; ?>][security_template]" 
                                    class="large-text" rows="3" 
                                    placeholder="Use variables: {ssl_status}, {firewall_status}, {backup_status}, {monitoring_status}"><?php echo esc_textarea($config['security_template'] ?? ''); ?></textarea>
                          <p class="description">
                            <strong>Available Variables:</strong><br>
                            <code>{ssl_status}</code> - SSL certificate status<br>
                            <code>{firewall_status}</code> - Firewall protection status<br>
                            <code>{backup_status}</code> - Backup information<br>
                            <code>{monitoring_status}</code> - Security monitoring details
                          </p>
                        </div>
                        <div class="luna-keyword-field">
                          <label>Shortcode Generator:</label>
                          <select onchange="luna_insert_shortcode(this.value, 'keywords[<?php echo $category; ?>][<?php echo $action; ?>][security_template]')">
                            <option value="">Select a shortcode to insert...</option>
                            <option value="{ssl_status}">SSL Status</option>
                            <option value="{firewall_status}">Firewall Status</option>
                            <option value="{backup_status}">Backup Status</option>
                            <option value="{monitoring_status}">Monitoring Status</option>
                          </select>
                        </div>
                      </div>
                      
                      <!-- Custom Response Options -->
                      <div class="luna-data-source-options luna-custom-options" 
                           style="display: <?php echo $data_source === 'custom' ? 'block' : 'none'; ?>;">
                        <div class="luna-response-type">
                          <label>
                            <input type="radio" name="keywords[<?php echo $category; ?>][<?php echo $action; ?>][response_type]" 
                                   value="simple" <?php checked($config['response_type'] ?? 'simple', 'simple'); ?> 
                                   onchange="luna_toggle_response_type('<?php echo $category; ?>', '<?php echo $action; ?>', 'simple')">
                            Simple Text Response
                          </label>
                          <label>
                            <input type="radio" name="keywords[<?php echo $category; ?>][<?php echo $action; ?>][response_type]" 
                                   value="advanced" <?php checked($config['response_type'] ?? 'simple', 'advanced'); ?> 
                                   onchange="luna_toggle_response_type('<?php echo $category; ?>', '<?php echo $action; ?>', 'advanced')">
                            Advanced Conversation Flows
                          </label>
                        </div>
                        
                        <!-- Simple Text Response -->
                        <div class="luna-simple-response" 
                             style="display: <?php echo ($config['response_type'] ?? 'simple') === 'simple' ? 'block' : 'none'; ?>;">
                          <div class="luna-keyword-field">
                            <label>Response Template:</label>
                            <textarea name="keywords[<?php echo $category; ?>][<?php echo $action; ?>][template]" 
                                      class="large-text" rows="3" 
                                      placeholder="Enter your response template..."><?php echo esc_textarea($template); ?></textarea>
                            <p class="description">
                              <strong>Available Shortcodes:</strong><br>
                              <code>[contact_page]</code> - Link to contact page<br>
                              <code>[booking_link]</code> - Link to booking page<br>
                              <code>[phone_number]</code> - Phone number link<br>
                              <code>[email_link]</code> - Email link<br>
                              <code>[site_url]</code> - Site URL<br>
                              <code>[business_name]</code> - Business name
                            </p>
                          </div>
                          <div class="luna-keyword-field">
                            <label>Shortcode Generator:</label>
                            <select onchange="luna_insert_shortcode(this.value, 'keywords[<?php echo $category; ?>][<?php echo $action; ?>][template]')">
                              <option value="">Select a shortcode to insert...</option>
                              <option value="[contact_page]">Contact Page Link</option>
                              <option value="[booking_link]">Booking Link</option>
                              <option value="[phone_number]">Phone Number</option>
                              <option value="[email_link]">Email Link</option>
                              <option value="[site_url]">Site URL</option>
                              <option value="[business_name]">Business Name</option>
                            </select>
                          </div>
                        </div>
                        
                        <!-- Advanced Conversation Flows -->
                        <div class="luna-advanced-response" 
                             style="display: <?php echo ($config['response_type'] ?? 'simple') === 'advanced' ? 'block' : 'none'; ?>;">
                          <div class="luna-keyword-field">
                            <label>Initial Response:</label>
                            <textarea name="keywords[<?php echo $category; ?>][<?php echo $action; ?>][initial_response]" 
                                      class="large-text" rows="2" 
                                      placeholder="What should Luna say first?"><?php echo esc_textarea($config['initial_response'] ?? ''); ?></textarea>
                          </div>
                          <div class="luna-keyword-field">
                            <label>Follow-up Responses:</label>
                            <div class="luna-branch-responses">
                              <div class="luna-branch-item">
                                <input type="text" name="keywords[<?php echo $category; ?>][<?php echo $action; ?>][branches][yes][trigger]" 
                                       placeholder="User says (e.g., 'yes', 'sure', 'okay')" 
                                       value="<?php echo esc_attr($config['branches']['yes']['trigger'] ?? 'yes'); ?>">
                                <textarea name="keywords[<?php echo $category; ?>][<?php echo $action; ?>][branches][yes][response]" 
                                          placeholder="Luna responds..." 
                                          rows="2"><?php echo esc_textarea($config['branches']['yes']['response'] ?? ''); ?></textarea>
                              </div>
                              <div class="luna-branch-item">
                                <input type="text" name="keywords[<?php echo $category; ?>][<?php echo $action; ?>][branches][no][trigger]" 
                                       placeholder="User says (e.g., 'no', 'not now', 'maybe later')" 
                                       value="<?php echo esc_attr($config['branches']['no']['trigger'] ?? 'no'); ?>">
                                <textarea name="keywords[<?php echo $category; ?>][<?php echo $action; ?>][branches][no][response]" 
                                          placeholder="Luna responds..." 
                                          rows="2"><?php echo esc_textarea($config['branches']['no']['response'] ?? ''); ?></textarea>
                              </div>
                              <div class="luna-branch-item">
                                <input type="text" name="keywords[<?php echo $category; ?>][<?php echo $action; ?>][branches][maybe][trigger]" 
                                       placeholder="User says (e.g., 'maybe', 'not sure', 'tell me more')" 
                                       value="<?php echo esc_attr($config['branches']['maybe']['trigger'] ?? 'maybe'); ?>">
                                <textarea name="keywords[<?php echo $category; ?>][<?php echo $action; ?>][branches][maybe][response]" 
                                          placeholder="Luna responds..." 
                                          rows="2"><?php echo esc_textarea($config['branches']['maybe']['response'] ?? ''); ?></textarea>
                              </div>
                            </div>
                            <p class="description">Define how Luna should respond based on different user inputs.</p>
                          </div>
                        </div>
                      </div>
                    </div>
                  </td>
                </tr>
              <?php endforeach; ?>
            </table>
          </div>
        <?php endforeach; ?>
      </div>
      
      <p class="submit">
        <input type="submit" name="save_keywords" class="button-primary" value="Save Keywords & Templates">
        <a href="#" class="button" onclick="luna_export_keywords(); return false;">Export Keywords</a>
        <a href="#" class="button" onclick="luna_import_keywords(); return false;">Import Keywords</a>
      </p>
    </form>
  </div>
  
  <style>
    .luna-keywords-container {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
      gap: 20px;
      margin: 20px 0;
    }
    .luna-keyword-category {
      border: 1px solid #ddd;
      padding: 15px;
      border-radius: 5px;
      background: #f9f9f9;
    }
    .luna-keyword-category h3 {
      margin-top: 0;
      color: #23282d;
    }
    .luna-keyword-config {
      display: flex;
      flex-direction: column;
      gap: 10px;
    }
    .luna-keyword-field {
      display: flex;
      flex-direction: column;
    }
    .luna-keyword-field label {
      font-weight: bold;
      margin-bottom: 5px;
    }
    .luna-keywords-help {
      background: #e7f3ff;
      border: 1px solid #0073aa;
      border-radius: 5px;
      padding: 15px;
      margin: 20px 0;
    }
    .luna-keywords-help h3 {
      margin-top: 0;
      color: #0073aa;
    }
    .luna-keywords-help code {
      background: #fff;
      padding: 2px 4px;
      border-radius: 3px;
      font-family: monospace;
    }
    
    /* Modal Styles */
    .luna-modal {
      position: fixed;
      z-index: 100000;
      left: 0;
      top: 0;
      width: 100%;
      height: 100%;
      background-color: rgba(0, 0, 0, 0.5);
      display: flex;
      align-items: center;
      justify-content: center;
    }
    
    .luna-modal-content {
      background-color: #fff;
      border-radius: 4px;
      box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
      width: 90%;
      max-width: 600px;
      max-height: 90vh;
      overflow-y: auto;
    }
    
    .luna-modal-header {
      padding: 20px;
      border-bottom: 1px solid #ddd;
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: #f1f1f1;
    }
    
    .luna-modal-header h2 {
      margin: 0;
      font-size: 18px;
    }
    
    .luna-modal-close {
      font-size: 24px;
      font-weight: bold;
      cursor: pointer;
      color: #666;
    }
    
    .luna-modal-close:hover {
      color: #000;
    }
    
    .luna-modal-body {
      padding: 20px;
    }
    
    .luna-modal-footer {
      padding: 20px;
      border-top: 1px solid #ddd;
      text-align: right;
      background: #f9f9f9;
    }
    
    .luna-modal-footer .button {
      margin-left: 10px;
    }
    
    .keyword-management-item {
      display: flex;
      align-items: center;
      padding: 10px;
      border: 1px solid #ddd;
      border-radius: 4px;
      margin-bottom: 10px;
      background: #fff;
    }
    
    .keyword-management-item select {
      margin-left: 10px;
      min-width: 150px;
    }
    
    .keyword-management-item .keyword-info {
      flex: 1;
    }
    
    .keyword-management-item .keyword-name {
      font-weight: 600;
    }
    
    .keyword-management-item .keyword-terms {
      color: #666;
      font-size: 12px;
    }
  </style>
  
  <script>
    function luna_export_keywords() {
      // TODO: Implement keyword export functionality
      alert('Export functionality coming soon!');
    }
    
  function luna_import_keywords() {
    // TODO: Implement keyword import functionality
    alert('Import functionality coming soon!');
  }
  
  // Chat transcript functionality
  function showLunaChatTranscript(licenseKey) {
    // Create modal if it doesn't exist
    if (!document.getElementById('luna-chat-transcript-modal')) {
      var modal = document.createElement('div');
      modal.id = 'luna-chat-transcript-modal';
      modal.className = 'luna-modal';
      modal.innerHTML = `
        <div class="luna-modal-content">
          <div class="luna-modal-header">
            <h3>Luna Chat Transcript - License: ${licenseKey}</h3>
            <span class="luna-modal-close" onclick="closeLunaChatTranscript()">&times;</span>
          </div>
          <div class="luna-modal-body" id="luna-chat-transcript-content">
            <p>Loading chat transcript...</p>
          </div>
          <div class="luna-modal-footer" style="margin-top: 20px; text-align: right;">
            <button type="button" class="button" onclick="closeLunaChatTranscript()">Close</button>
          </div>
        </div>
      `;
      document.body.appendChild(modal);
    }
    
    // Show modal
    document.getElementById('luna-chat-transcript-modal').style.display = 'block';
    
    // Load transcript data
    loadLunaChatTranscript(licenseKey);
  }
  
  function closeLunaChatTranscript() {
    document.getElementById('luna-chat-transcript-modal').style.display = 'none';
  }
  
  function loadLunaChatTranscript(licenseKey) {
    // Make AJAX request to get chat transcript
    jQuery.ajax({
      url: '<?php echo admin_url('admin-ajax.php'); ?>',
      type: 'POST',
      data: {
        action: 'luna_get_chat_transcript',
        license_key: licenseKey,
        nonce: '<?php echo wp_create_nonce('luna_chat_transcript_nonce'); ?>'
      },
      success: function(response) {
        if (response.success) {
          var content = document.getElementById('luna-chat-transcript-content');
          if (response.data.transcript && response.data.transcript.length > 0) {
            var html = '<div class="luna-chat-transcript">';
            response.data.transcript.forEach(function(entry) {
              html += '<div class="luna-chat-entry ' + entry.type + '">';
              html += '<div style="font-weight: bold; color: #333; margin-bottom: 5px;">';
              html += (entry.type === 'user' ? '👤 User' : '🤖 Luna') + ' - ' + entry.timestamp;
              html += '</div>';
              html += '<div style="color: #555;">' + entry.message + '</div>';
              html += '</div>';
            });
            html += '</div>';
            content.innerHTML = html;
          } else {
            content.innerHTML = '<p>No chat transcript available for this license.</p>';
          }
        } else {
          document.getElementById('luna-chat-transcript-content').innerHTML = '<p>Error loading chat transcript: ' + response.data + '</p>';
        }
      },
      error: function() {
        document.getElementById('luna-chat-transcript-content').innerHTML = '<p>Error loading chat transcript. Please try again.</p>';
      }
    });
  }
  
  // Close modal when clicking outside
  window.onclick = function(event) {
    var modal = document.getElementById('luna-chat-transcript-modal');
    if (event.target === modal) {
      closeLunaChatTranscript();
    }
  }
  </script>
  <?php
}

// Analytics admin page
function luna_widget_analytics_admin_page() {
  $performance = luna_get_keyword_performance();
  ?>
  <div class="wrap">
    <h1>Luna Chat Analytics</h1>
    <p>Track keyword performance and usage statistics to optimize your Luna Chat experience.</p>
    
    <div class="notice notice-info">
      <p><strong>Note:</strong> GA4 Analytics integration has been moved to the <a href="https://visiblelight.ai/wp-admin/admin.php?page=vl-hub-profile" target="_blank">VL Client Hub Profile</a> for centralized management.</p>
    </div>
    
    <!-- Interactions Metric -->
    <div class="postbox" style="margin-top: 20px;">
      <h2 class="hndle">Chat Interactions</h2>
      <div class="inside">
        <?php
        $interactions_count = luna_get_interactions_count();
        $license = luna_get_license();
        ?>
        <div class="luna-interactions-metric" style="text-align: center; padding: 20px; background: #f9f9f9; border-radius: 5px; cursor: pointer;" onclick="showLunaChatTranscript('<?php echo esc_js($license); ?>')">
          <div style="font-size: 3em; font-weight: bold; color: #0073aa; margin-bottom: 10px;"><?php echo $interactions_count; ?></div>
          <div style="font-size: 1.2em; color: #666;">Total Interactions</div>
          <div style="font-size: 0.9em; color: #999; margin-top: 5px;">Click to view chat transcript</div>
        </div>
      </div>
    </div>
    
    <?php if (empty($performance)): ?>
      <div class="notice notice-info">
        <p>No keyword usage data available yet. Start using Luna Chat to see analytics!</p>
      </div>
    <?php else: ?>
      <div class="luna-analytics-container">
        <div class="luna-analytics-summary">
          <h3>Summary</h3>
          <div class="luna-stats-grid">
            <div class="luna-stat-box">
              <h4>Total Keywords Used</h4>
              <span class="luna-stat-number"><?php echo count($performance); ?></span>
            </div>
            <div class="luna-stat-box">
              <h4>Total Interactions</h4>
              <span class="luna-stat-number"><?php echo array_sum(array_column($performance, 'total_uses')); ?></span>
            </div>
            <div class="luna-stat-box">
              <h4>Average Success Rate</h4>
              <span class="luna-stat-number"><?php 
                $avg_success = array_sum(array_column($performance, 'success_rate')) / count($performance);
                echo round($avg_success, 1) . '%';
              ?></span>
            </div>
          </div>
        </div>
        
        <div class="luna-analytics-details">
          <h3>Keyword Performance</h3>
          <table class="wp-list-table widefat fixed striped">
            <thead>
              <tr>
                <th>Keyword</th>
                <th>Category</th>
                <th>Total Uses</th>
                <th>Success Rate</th>
                <th>Last Used</th>
              </tr>
            </thead>
            <tbody>
              <?php foreach ($performance as $key => $stats): ?>
                <?php 
                list($category, $action) = explode('.', $key, 2);
                $success_class = $stats['success_rate'] >= 80 ? 'success' : ($stats['success_rate'] >= 60 ? 'warning' : 'error');
                ?>
                <tr>
                  <td><strong><?php echo esc_html(ucfirst($action)); ?></strong></td>
                  <td><?php echo esc_html(ucfirst($category)); ?></td>
                  <td><?php echo $stats['total_uses']; ?></td>
                  <td>
                    <span class="luna-success-rate luna-<?php echo $success_class; ?>">
                      <?php echo $stats['success_rate']; ?>%
                    </span>
                  </td>
                  <td><?php echo esc_html($stats['last_used']); ?></td>
                </tr>
              <?php endforeach; ?>
            </tbody>
          </table>
        </div>
        
        <div class="luna-analytics-insights">
          <h3>Insights & Recommendations</h3>
          <div class="luna-insights">
            <?php
            $low_performing = array_filter($performance, function($stats) {
              return $stats['success_rate'] < 60 && $stats['total_uses'] > 2;
            });
            
            $unused = array_filter($performance, function($stats) {
              return $stats['total_uses'] == 0;
            });
            
            $high_performing = array_filter($performance, function($stats) {
              return $stats['success_rate'] >= 90 && $stats['total_uses'] > 5;
            });
            ?>
            
            <?php if (!empty($low_performing)): ?>
              <div class="luna-insight warning">
                <h4>⚠️ Low Performing Keywords</h4>
                <p>These keywords have low success rates and may need attention:</p>
                <ul>
                  <?php foreach ($low_performing as $key => $stats): ?>
                    <li><strong><?php echo esc_html(ucfirst(explode('.', $key)[1])); ?></strong> - <?php echo $stats['success_rate']; ?>% success rate</li>
                  <?php endforeach; ?>
                </ul>
                <p><em>Consider reviewing the response templates or adding more specific keywords.</em></p>
              </div>
            <?php endif; ?>
            
            <?php if (!empty($high_performing)): ?>
              <div class="luna-insight success">
                <h4>✅ High Performing Keywords</h4>
                <p>These keywords are working well:</p>
                <ul>
                  <?php foreach ($high_performing as $key => $stats): ?>
                    <li><strong><?php echo esc_html(ucfirst(explode('.', $key)[1])); ?></strong> - <?php echo $stats['success_rate']; ?>% success rate</li>
                  <?php endforeach; ?>
                </ul>
                <p><em>Great job! These responses are working effectively.</em></p>
              </div>
            <?php endif; ?>
            
            <?php if (empty($low_performing) && empty($high_performing)): ?>
              <div class="luna-insight info">
                <h4>📊 Keep Using Luna Chat</h4>
                <p>Continue using Luna Chat to build up more performance data. The more interactions you have, the better insights we can provide!</p>
              </div>
            <?php endif; ?>
          </div>
        </div>
      </div>
    <?php endif; ?>
  </div>
  
  <style>
    .luna-analytics-container {
      display: flex;
      flex-direction: column;
      gap: 30px;
    }
    .luna-stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 20px;
      margin: 20px 0;
    }
    .luna-stat-box {
      background: #f8f9fa;
      border: 1px solid #dee2e6;
      border-radius: 8px;
      padding: 20px;
      text-align: center;
    }
    .luna-stat-box h4 {
      margin: 0 0 10px 0;
      color: #6c757d;
      font-size: 14px;
      font-weight: 600;
    }
    .luna-stat-number {
      font-size: 32px;
      font-weight: bold;
      color: #0073aa;
    }
    .luna-success-rate {
      padding: 4px 8px;
      border-radius: 4px;
      font-weight: bold;
    }
    .luna-success-rate.luna-success {
      background: #d4edda;
      color: #155724;
    }
    .luna-success-rate.luna-warning {
      background: #fff3cd;
      color: #856404;
    }
    .luna-success-rate.luna-error {
      background: #f8d7da;
      color: #721c24;
    }
    .luna-insights {
      display: flex;
      flex-direction: column;
      gap: 20px;
    }
    .luna-insight {
      padding: 20px;
      border-radius: 8px;
      border-left: 4px solid;
    }
    .luna-insight.success {
      background: #d4edda;
      border-left-color: #28a745;
    }
    .luna-insight.warning {
      background: #fff3cd;
      border-left-color: #ffc107;
    }
    .luna-composer__response, [data-luna-composer] .luna-composer__response{display:none !important;}
    [data-luna-composer] .luna-composer__response[data-loading="true"], [data-luna-composer] .luna-composer__response[data-loading="false"] {
        display: inline !important;
    }
    .luna-insight.info {
      background: #d1ecf1;
      border-left-color: #17a2b8;
    }
    .luna-insight h4 {
      margin-top: 0;
    }
    .luna-insight ul {
      margin: 10px 0;
    }
    
    /* Chat Transcript Modal Styles */
    .luna-modal {
      position: fixed;
      z-index: 100000;
      left: 0;
      top: 0;
      width: 100%;
      height: 100%;
      background-color: rgba(0,0,0,0.5);
      display: none;
    }
    
    .luna-modal-content {
      background-color: #fff;
      margin: 5% auto;
      padding: 20px;
      border-radius: 8px;
      width: 80%;
      max-width: 800px;
      max-height: 80vh;
      overflow-y: auto;
    }
    
    .luna-modal-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 20px;
      padding-bottom: 10px;
      border-bottom: 1px solid #ddd;
    }
    
    .luna-modal-close {
      font-size: 24px;
      font-weight: bold;
      cursor: pointer;
      color: #666;
    }
    
    .luna-chat-transcript {
      max-height: 400px;
      overflow-y: auto;
      border: 1px solid #ddd;
      padding: 15px;
      background: #f9f9f9;
    }
    
    .luna-chat-entry {
      margin-bottom: 15px;
      padding: 10px;
      border-radius: 5px;
    }
    
    .luna-chat-entry.user {
      background: #e3f2fd;
    }
    
    .luna-chat-entry.assistant {
      background: #f5f5f5;
    }
    
    /* Keyword Interface Styles */
    .luna-data-source-options {
      margin-top: 15px;
      padding: 15px;
      background: #f8f9fa;
      border: 1px solid #dee2e6;
      border-radius: 6px;
    }
    
    .luna-response-type {
      margin-bottom: 15px;
    }
    
    .luna-response-type label {
      display: inline-block;
      margin-right: 20px;
      font-weight: 600;
    }
    
    .luna-response-type input[type="radio"] {
      margin-right: 8px;
    }
    
    .luna-branch-responses {
      display: flex;
      flex-direction: column;
      gap: 15px;
    }
    
    .luna-branch-item {
      display: flex;
      flex-direction: column;
      gap: 8px;
      padding: 12px;
      background: #ffffff;
      border: 1px solid #e9ecef;
      border-radius: 4px;
    }
    
    .luna-branch-item input[type="text"] {
      padding: 8px 12px;
      border: 1px solid #ced4da;
      border-radius: 4px;
      font-size: 14px;
    }
    
    .luna-branch-item textarea {
      padding: 8px 12px;
      border: 1px solid #ced4da;
      border-radius: 4px;
      font-size: 14px;
      resize: vertical;
    }
    
    .luna-keyword-field .description {
      margin-top: 8px;
      font-size: 13px;
      color: #6c757d;
      line-height: 1.4;
    }
    
    .luna-keyword-field .description code {
      background: #e9ecef;
      padding: 2px 4px;
      border-radius: 3px;
      font-family: 'Courier New', monospace;
      font-size: 12px;
    }
    
    .luna-keyword-field select {
      padding: 6px 10px;
      border: 1px solid #ced4da;
      border-radius: 4px;
      font-size: 14px;
    }
  </style>
  <?php
}

// Separate function for JavaScript
function luna_keywords_admin_scripts() {
  ?>
  <script>
  function luna_toggle_keyword(category, action) {
    const checkbox = document.querySelector(`input[name="keywords[${category}][${action}][enabled]"]`);
    const row = checkbox.closest('tr');
    const inputs = row.querySelectorAll('input, textarea, select');
    
    inputs.forEach(input => {
      if (input !== checkbox) {
        input.disabled = !checkbox.checked;
      }
    });
  }
  
  function luna_toggle_data_source_options(select, category, action) {
    const dataSource = select.value;
    const row = select.closest('tr');
    
    console.log('Luna Keywords: Toggling data source to', dataSource, 'for', category, action);
    
    // Hide all data source options
    row.querySelectorAll('.luna-data-source-options').forEach(div => {
      div.style.display = 'none';
    });
    
    // Show the selected data source options
    const targetDiv = row.querySelector(`.luna-${dataSource}-options`);
    if (targetDiv) {
      targetDiv.style.display = 'block';
      console.log('Luna Keywords: Showing', dataSource, 'options');
      
      // If it's custom response, also initialize the response type
      if (dataSource === 'custom') {
        const checkedRadio = targetDiv.querySelector('input[name*="[response_type]"]:checked');
        if (checkedRadio) {
          console.log('Luna Keywords: Found checked radio, initializing response type');
          luna_toggle_response_type(category, action, checkedRadio.value);
        }
      }
    } else {
      console.log('Luna Keywords: Target div not found for', dataSource);
    }
  }
  
  function luna_toggle_response_type(category, action, type) {
    const radio = document.querySelector(`input[name="keywords[${category}][${action}][response_type]"][value="${type}"]`);
    if (!radio) {
      console.log('Luna Keywords: Radio not found for', category, action, type);
      return;
    }
    
    const row = radio.closest('tr');
    
    console.log('Luna Keywords: Toggling response type to', type, 'for', category, action);
    
    // Hide both response types
    row.querySelectorAll('.luna-simple-response, .luna-advanced-response').forEach(div => {
      div.style.display = 'none';
    });
    
    // Show the selected response type
    const targetDiv = row.querySelector(`.luna-${type}-response`);
    if (targetDiv) {
      targetDiv.style.display = 'block';
      console.log('Luna Keywords: Showing', type, 'response');
    } else {
      console.log('Luna Keywords: Target div not found for', type, 'response');
    }
  }
  
  function luna_insert_shortcode(shortcode, targetFieldName) {
    if (!shortcode) return;
    
    const textarea = document.querySelector(`textarea[name="${targetFieldName}"]`);
    if (textarea) {
      const start = textarea.selectionStart;
      const end = textarea.selectionEnd;
      const text = textarea.value;
      const before = text.substring(0, start);
      const after = text.substring(end, text.length);
      
      textarea.value = before + shortcode + after;
      textarea.focus();
      textarea.setSelectionRange(start + shortcode.length, start + shortcode.length);
    }
  }
  
  // Modal functionality
  function openModal(modalId) {
    document.getElementById(modalId).style.display = 'flex';
  }
  
  function closeModal(modalId) {
    document.getElementById(modalId).style.display = 'none';
  }
  
  // Add new keyword functionality
  function addNewKeyword() {
    openModal('keyword-modal');
  }
  
  function saveNewKeyword() {
    const category = document.getElementById('new-keyword-category').value;
    const action = document.getElementById('new-keyword-name').value;
    const terms = document.getElementById('new-keyword-terms').value;
    const dataSource = document.getElementById('new-keyword-data-source').value;
    const template = document.getElementById('new-keyword-template').value;
    
    if (!action || !terms) {
      alert('Please fill in the keyword name and terms.');
      return;
    }
    
    // Create new keyword row
    const container = document.querySelector('.luna-keywords-container');
    const newRow = document.createElement('div');
    newRow.className = 'luna-keyword-category';
    newRow.innerHTML = `
      <h3>${category.charAt(0).toUpperCase() + category.slice(1)} Keywords</h3>
      <table class="form-table">
        <tr>
          <th scope="row">${action.charAt(0).toUpperCase() + action.slice(1)}</th>
          <td>
            <div class="luna-keyword-config">
              <div class="luna-keyword-field">
                <label>
                  <input type="checkbox" name="keywords[${category}][${action}][enabled]" value="on" checked onchange="luna_toggle_keyword('${category}', '${action}')">
                  Enable this keyword
                </label>
              </div>
              <div class="luna-keyword-field">
                <label>Keywords:</label>
                <input type="text" name="keywords[${category}][${action}][terms]" class="regular-text" value="${terms}">
              </div>
              <div class="luna-keyword-field">
                <label>Data Source:</label>
                <select name="keywords[${category}][${action}][data_source]" onchange="luna_toggle_data_source_options(this, '${category}', '${action}')">
                  <option value="custom" ${dataSource === 'custom' ? 'selected' : ''}>Custom Response</option>
                  <option value="wp_rest" ${dataSource === 'wp_rest' ? 'selected' : ''}>WordPress Data</option>
                  <option value="security" ${dataSource === 'security' ? 'selected' : ''}>Security Data</option>
                </select>
              </div>
              <div class="luna-keyword-field">
                <label>Response Template:</label>
                <textarea name="keywords[${category}][${action}][template]" class="large-text" rows="3">${template}</textarea>
              </div>
            </div>
          </td>
        </tr>
      </table>
    `;
    
    // Add to container
    container.appendChild(newRow);
    
    // Initialize the new keyword
    luna_toggle_keyword(category, action);
    
    // Clear form and close modal
    document.getElementById('new-keyword-name').value = '';
    document.getElementById('new-keyword-terms').value = '';
    document.getElementById('new-keyword-template').value = '';
    closeModal('keyword-modal');
  }
  
  // Add new category functionality
  function addNewCategory() {
    openModal('category-modal');
  }
  
  function saveNewCategory() {
    const categoryName = document.getElementById('new-category-name').value;
    const description = document.getElementById('new-category-description').value;
    
    if (!categoryName) {
      alert('Please enter a category name.');
      return;
    }
    
    // Add to category dropdown
    const categorySelect = document.getElementById('new-keyword-category');
    const newOption = document.createElement('option');
    newOption.value = categoryName.toLowerCase().replace(/\s+/g, '_');
    newOption.textContent = categoryName.charAt(0).toUpperCase() + categoryName.slice(1);
    categorySelect.appendChild(newOption);
    
    // Clear form and close modal
    document.getElementById('new-category-name').value = '';
    document.getElementById('new-category-description').value = '';
    closeModal('category-modal');
    
    alert(`Category "${categoryName}" added successfully! You can now use it when adding new keywords.`);
  }
  
  // Manage existing keywords functionality
  function manageKeywords() {
    const container = document.getElementById('keyword-management-list');
    container.innerHTML = '';
    
    // Get all existing keywords
    const keywords = [];
    document.querySelectorAll('.luna-keyword-category').forEach(categoryDiv => {
      const categoryName = categoryDiv.querySelector('h3').textContent.replace(' Keywords', '').toLowerCase();
      categoryDiv.querySelectorAll('tr').forEach(row => {
        const th = row.querySelector('th');
        if (th && th.textContent.trim()) {
          const actionName = th.textContent.trim();
          const termsInput = row.querySelector('input[name*="[terms]"]');
          const terms = termsInput ? termsInput.value : '';
          
          keywords.push({
            category: categoryName,
            action: actionName,
            terms: terms,
            element: row
          });
        }
      });
    });
    
    // Create management interface
    keywords.forEach(keyword => {
      const item = document.createElement('div');
      item.className = 'keyword-management-item';
      item.innerHTML = `
        <div class="keyword-info">
          <div class="keyword-name">${keyword.action}</div>
          <div class="keyword-terms">${keyword.terms}</div>
        </div>
        <select data-category="${keyword.category}" data-action="${keyword.action}">
          <option value="business" ${keyword.category === 'business' ? 'selected' : ''}>Business</option>
          <option value="wp_rest" ${keyword.category === 'wp_rest' ? 'selected' : ''}>WordPress Data</option>
          <option value="security" ${keyword.category === 'security' ? 'selected' : ''}>Security</option>
          <option value="custom" ${keyword.category === 'custom' ? 'selected' : ''}>Custom</option>
        </select>
      `;
      container.appendChild(item);
    });
    
    openModal('manage-modal');
  }
  
  function saveKeywordChanges() {
    const changes = [];
    document.querySelectorAll('#keyword-management-list select').forEach(select => {
      const category = select.dataset.category;
      const action = select.dataset.action;
      const newCategory = select.value;
      
      if (category !== newCategory) {
        changes.push({ category, action, newCategory });
      }
    });
    
    if (changes.length === 0) {
      closeModal('manage-modal');
      return;
    }
    
    // Apply changes
    changes.forEach(change => {
      // Find the row and move it to the new category
      const row = document.querySelector(`input[name*="[${change.action}][enabled]"]`).closest('tr');
      const categoryDiv = row.closest('.luna-keyword-category');
      
      // Update the category name in the row
      const categorySelect = row.querySelector('select[name*="[data_source]"]');
      if (categorySelect) {
        const name = categorySelect.name;
        const newName = name.replace(`[${change.category}]`, `[${change.newCategory}]`);
        categorySelect.name = newName;
      }
      
      // Update all form elements in the row
      row.querySelectorAll('input, select, textarea').forEach(input => {
        if (input.name && input.name.includes(`[${change.category}]`)) {
          input.name = input.name.replace(`[${change.category}]`, `[${change.newCategory}]`);
        }
      });
    });
    
    closeModal('manage-modal');
    alert(`Moved ${changes.length} keyword(s) to new categories. Don't forget to save the form!`);
  }
  
  // Initialize the interface on page load
  document.addEventListener('DOMContentLoaded', function() {
    console.log('Luna Keywords: Initializing interface...');
    
    // Button event listeners
    document.getElementById('add-new-keyword').addEventListener('click', addNewKeyword);
    document.getElementById('add-new-category').addEventListener('click', addNewCategory);
    document.getElementById('manage-keywords').addEventListener('click', manageKeywords);
    
    // Modal event listeners
    document.getElementById('save-new-keyword').addEventListener('click', saveNewKeyword);
    document.getElementById('cancel-new-keyword').addEventListener('click', () => closeModal('keyword-modal'));
    document.getElementById('save-new-category').addEventListener('click', saveNewCategory);
    document.getElementById('cancel-new-category').addEventListener('click', () => closeModal('category-modal'));
    document.getElementById('save-keyword-changes').addEventListener('click', saveKeywordChanges);
    document.getElementById('cancel-keyword-changes').addEventListener('click', () => closeModal('manage-modal'));
    
    // Close modal when clicking X
    document.querySelectorAll('.luna-modal-close').forEach(closeBtn => {
      closeBtn.addEventListener('click', function() {
        const modal = this.closest('.luna-modal');
        modal.style.display = 'none';
      });
    });
    
    // Close modal when clicking outside
    document.querySelectorAll('.luna-modal').forEach(modal => {
      modal.addEventListener('click', function(e) {
        if (e.target === this) {
          this.style.display = 'none';
        }
      });
    });
    
    // Initialize all data source options
    document.querySelectorAll('select[name*="[data_source]"]').forEach(select => {
      const categoryMatch = select.name.match(/keywords\[([^\]]+)\]/);
      const actionMatch = select.name.match(/\[([^\]]+)\]\[data_source\]/);
      
      if (categoryMatch && actionMatch) {
        const category = categoryMatch[1];
        const action = actionMatch[1];
        console.log('Luna Keywords: Initializing data source for', category, action, '=', select.value);
        luna_toggle_data_source_options(select, category, action);
      }
    });
    
    // Initialize all response types for custom responses
    document.querySelectorAll('input[name*="[response_type]"]:checked').forEach(radio => {
      const categoryMatch = radio.name.match(/keywords\[([^\]]+)\]/);
      const actionMatch = radio.name.match(/\[([^\]]+)\]\[response_type\]/);
      
      if (categoryMatch && actionMatch) {
        const category = categoryMatch[1];
        const action = actionMatch[1];
        const type = radio.value;
        console.log('Luna Keywords: Initializing response type for', category, action, '=', type);
        luna_toggle_response_type(category, action, type);
      }
    });
  });
  </script>
  <?php
}

/* ============================================================
 * SECURITY HELPERS
 * ============================================================ */
function luna_license_ok( WP_REST_Request $req ) {
  $saved = (string) get_option(LUNA_WIDGET_OPT_LICENSE, '');
  if ($saved === '') return false;
  $hdr = trim((string) ($req->get_header('X-Luna-License') ? $req->get_header('X-Luna-License') : ''));
  $qp  = trim((string) $req->get_param('license'));
  $provided = $hdr ? $hdr : $qp;
  if (!$provided) return false;
  if (!is_ssl() && $qp) return false; // only allow license in query over https
  return hash_equals($saved, $provided);
}
function luna_forbidden() {
  return new WP_REST_Response(array('ok'=>false,'error'=>'forbidden'), 403);
}

/**
 * Analyzes help requests and offers contextual assistance options
 */
function luna_analyze_help_request($prompt, $facts) {
  $help_type = luna_detect_help_type($prompt);
  $site_url = isset($facts['site_url']) ? $facts['site_url'] : home_url('/');
  $site_name = parse_url($site_url, PHP_URL_HOST);
  
  $response = "I understand you're experiencing an issue. Let me help you get this resolved quickly! ";
  
  switch ($help_type) {
    case 'technical':
      $response .= "This sounds like a technical issue. I can help you in a few ways:\n\n";
      $response .= "🔧 **Option 1: Send Support Email**\n";
      $response .= "I can send a detailed snapshot of our conversation and your site data to your email for technical review.\n\n";
      $response .= "📧 **Option 2: Notify Visible Light Team**\n";
      $response .= "I can alert the Visible Light support team about this issue.\n\n";
      $response .= "🐛 **Option 3: Report as Bug**\n";
      $response .= "If this seems like a bug, I can report it directly to the development team.\n\n";
      $response .= "Which option would you prefer? Just say 'support email', 'notify VL', or 'report bug'.";
      break;
      
    case 'content':
      $response .= "This seems like a content or website management issue. I can help you by:\n\n";
      $response .= "📝 **Option 1: Content Support**\n";
      $response .= "Send your content team a detailed report of what you're trying to accomplish.\n\n";
      $response .= "📧 **Option 2: Notify Visible Light**\n";
      $response .= "Alert the Visible Light team about this content issue.\n\n";
      $response .= "Which would you prefer? Say 'support email' or 'notify VL'.";
      break;
      
    case 'urgent':
      $response .= "This sounds urgent! I can help you immediately by:\n\n";
      $response .= "🚨 **Option 1: Emergency Support**\n";
      $response .= "Send an urgent support request with full context to your team.\n\n";
      $response .= "📞 **Option 2: Notify Visible Light**\n";
      $response .= "Alert the Visible Light team immediately about this urgent issue.\n\n";
      $response .= "🐛 **Option 3: Report Critical Bug**\n";
      $response .= "If this is a critical bug, report it directly to development.\n\n";
      $response .= "Which option would you like? Say 'support email', 'notify VL', or 'report bug'.";
      break;
      
    default:
      $response .= "I can help you get this resolved. Here are your options:\n\n";
      $response .= "📧 **Option 1: Send Support Email**\n";
      $response .= "I'll send a detailed snapshot of our conversation to your email.\n\n";
      $response .= "📞 **Option 2: Notify Visible Light**\n";
      $response .= "I'll alert the Visible Light team about this issue.\n\n";
      $response .= "🐛 **Option 3: Report Bug**\n";
      $response .= "If this seems like a bug, I'll report it to the development team.\n\n";
      $response .= "Which option would you prefer? Just say 'support email', 'notify VL', or 'report bug'.";
  }
  
  return $response;
}

/**
 * Detects the type of help request based on keywords and context
 */
function luna_detect_help_type($prompt) {
  $lc = strtolower($prompt);
  
  // Urgent keywords
  if (preg_match('/\b(urgent|critical|emergency|down|crash|fatal|broken|not working|error|bug)\b/', $lc)) {
    return 'urgent';
  }
  
  // Technical keywords
  if (preg_match('/\b(technical|server|database|plugin|theme|code|php|mysql|error|bug|fix|repair)\b/', $lc)) {
    return 'technical';
  }
  
  // Content keywords
  if (preg_match('/\b(content|page|post|edit|update|publish|media|image|text|format)\b/', $lc)) {
    return 'content';
  }
  
  return 'general';
}

/**
 * Handles help option responses
 */
function luna_handle_help_option($option, $prompt, $facts) {
  switch ($option) {
    case 'support_email':
      return luna_handle_support_email_request($prompt, $facts);
    case 'notify_vl':
      return luna_handle_notify_vl_request($prompt, $facts);
    case 'report_bug':
      return luna_handle_bug_report_request($prompt, $facts);
    default:
      return "I'm not sure which option you meant. Please say 'support email', 'notify VL', or 'report bug'.";
  }
}

/**
 * Handles support email requests
 */
function luna_handle_support_email_request($prompt, $facts) {
  return "Great! I'd be happy to send you a detailed snapshot of our conversation and your site data. Which email address would you like me to send this to?";
}

/**
 * Handles Visible Light notification requests
 */
function luna_handle_notify_vl_request($prompt, $facts) {
  $site_url = isset($facts['site_url']) ? $facts['site_url'] : home_url('/');
  $site_name = parse_url($site_url, PHP_URL_HOST);
  
  // Send notification to Visible Light
  $success = luna_send_vl_notification($prompt, $facts);
  
  if ($success) {
    return "✅ I've notified the Visible Light team about your issue. They'll review the details and get back to you soon. Is there anything else I can help you with?";
  } else {
    return "I encountered an issue sending the notification. Let me try the support email option instead - which email address would you like me to send the snapshot to?";
  }
}

/**
 * Handles bug report requests
 */
function luna_handle_bug_report_request($prompt, $facts) {
  $site_url = isset($facts['site_url']) ? $facts['site_url'] : home_url('/');
  $site_name = parse_url($site_url, PHP_URL_HOST);
  
  // Send bug report to Visible Light
  $success = luna_send_bug_report($prompt, $facts);
  
  if ($success) {
    return "🐛 I've reported this as a bug to the Visible Light development team. They'll investigate and work on a fix. You should hear back soon. Is there anything else I can help you with?";
  } else {
    return "I encountered an issue sending the bug report. Let me try the support email option instead - which email address would you like me to send the snapshot to?";
  }
}

/**
 * Sends notification to Visible Light team
 */
function luna_send_vl_notification($prompt, $facts) {
  $site_url = isset($facts['site_url']) ? $facts['site_url'] : home_url('/');
  $site_name = parse_url($site_url, PHP_URL_HOST);
  $license = luna_get_license();
  
  $subject = "Luna Chat Support Request - " . $site_name;
  $message = "
  <html>
  <body style='font-family: Arial, sans-serif; line-height: 1.6; color: #333;'>
    <div style='max-width: 600px; margin: 0 auto; padding: 20px;'>
      <h2 style='color: #2B6AFF;'>Luna Chat Support Request</h2>
      <p><strong>Site:</strong> " . esc_html($site_name) . "</p>
      <p><strong>URL:</strong> " . esc_html($site_url) . "</p>
      <p><strong>License:</strong> " . esc_html($license) . "</p>
      <p><strong>Issue:</strong> " . esc_html($prompt) . "</p>
      
      <h3>Site Information:</h3>
      <ul>
        <li>WordPress Version: " . esc_html($facts['wp_version'] ?? 'Unknown') . "</li>
        <li>PHP Version: " . esc_html($facts['php_version'] ?? 'Unknown') . "</li>
        <li>Theme: " . esc_html($facts['theme'] ?? 'Unknown') . "</li>
        <li>Health Score: " . esc_html($facts['health_score'] ?? 'Unknown') . "%</li>
      </ul>
      
      <p>This request was generated automatically by Luna Chat AI.</p>
    </div>
  </body>
  </html>
  ";
  
  $headers = array('Content-Type: text/html; charset=UTF-8');
  return wp_mail('support@visiblelight.ai', $subject, $message, $headers);
}

/**
 * Sends bug report to Visible Light team
 */
function luna_send_bug_report($prompt, $facts) {
  $site_url = isset($facts['site_url']) ? $facts['site_url'] : home_url('/');
  $site_name = parse_url($site_url, PHP_URL_HOST);
  $license = luna_get_license();
  
  $subject = "🐛 Bug Report - " . $site_name . " - Luna Chat";
  $message = "
  <html>
  <body style='font-family: Arial, sans-serif; line-height: 1.6; color: #333;'>
    <div style='max-width: 600px; margin: 0 auto; padding: 20px;'>
      <h2 style='color: #d63638;'>🐛 Bug Report</h2>
      <p><strong>Site:</strong> " . esc_html($site_name) . "</p>
      <p><strong>URL:</strong> " . esc_html($site_url) . "</p>
      <p><strong>License:</strong> " . esc_html($license) . "</p>
      <p><strong>Bug Description:</strong> " . esc_html($prompt) . "</p>
      
      <h3>System Information:</h3>
      <ul>
        <li>WordPress Version: " . esc_html($facts['wp_version'] ?? 'Unknown') . "</li>
        <li>PHP Version: " . esc_html($facts['php_version'] ?? 'Unknown') . "</li>
        <li>Theme: " . esc_html($facts['theme'] ?? 'Unknown') . "</li>
        <li>Health Score: " . esc_html($facts['health_score'] ?? 'Unknown') . "%</li>
        <li>SSL Status: " . (isset($facts['tls_valid']) && $facts['tls_valid'] ? 'Active' : 'Issues') . "</li>
      </ul>
      
      <p>This bug report was generated automatically by Luna Chat AI.</p>
    </div>
  </body>
  </html>
  ";
  
  $headers = array('Content-Type: text/html; charset=UTF-8');
  return wp_mail('bugs@visiblelight.ai', $subject, $message, $headers);
}

/**
 * Extracts email address from text
 */
function luna_extract_email($text) {
  if (preg_match('/\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/', $text, $matches)) {
    return $matches[0];
  }
  return false;
}

/**
 * Sends support email with chat snapshot
 */
function luna_send_support_email($email, $prompt, $facts) {
  $site_url = isset($facts['site_url']) ? $facts['site_url'] : home_url('/');
  $site_name = parse_url($site_url, PHP_URL_HOST);
  $license = luna_get_license();
  
  $subject = "Luna Chat Support Snapshot - " . $site_name;
  $message = "
  <html>
  <body style='font-family: Arial, sans-serif; line-height: 1.6; color: #333;'>
    <div style='max-width: 600px; margin: 0 auto; padding: 20px;'>
      <h2 style='color: #2B6AFF;'>Luna Chat Support Snapshot</h2>
      <p>This email contains a detailed snapshot of your Luna Chat conversation and site data.</p>
      
      <h3>Site Information:</h3>
      <ul>
        <li><strong>Site:</strong> " . esc_html($site_name) . "</li>
        <li><strong>URL:</strong> " . esc_html($site_url) . "</li>
        <li><strong>License:</strong> " . esc_html($license) . "</li>
        <li><strong>WordPress Version:</strong> " . esc_html($facts['wp_version'] ?? 'Unknown') . "</li>
        <li><strong>PHP Version:</strong> " . esc_html($facts['php_version'] ?? 'Unknown') . "</li>
        <li><strong>Theme:</strong> " . esc_html($facts['theme'] ?? 'Unknown') . "</li>
        <li><strong>Health Score:</strong> " . esc_html($facts['health_score'] ?? 'Unknown') . "%</li>
        <li><strong>SSL Status:</strong> " . (isset($facts['tls_valid']) && $facts['tls_valid'] ? 'Active' : 'Issues') . "</li>
      </ul>
      
      <h3>Issue Description:</h3>
      <p>" . esc_html($prompt) . "</p>
      
      <h3>System Health Details:</h3>
      <ul>
        <li>Memory Usage: " . esc_html($facts['memory_usage'] ?? 'Unknown') . "</li>
        <li>Active Plugins: " . (isset($facts['active_plugins']) ? count($facts['active_plugins']) : 'Unknown') . "</li>
        <li>Pages: " . esc_html($facts['pages_count'] ?? 'Unknown') . "</li>
        <li>Posts: " . esc_html($facts['posts_count'] ?? 'Unknown') . "</li>
      </ul>
      
      <h3>Analytics Data:</h3>";
  
  if (isset($facts['ga4_metrics'])) {
    $ga4 = $facts['ga4_metrics'];
    $message .= "<ul>";
    $message .= "<li>Total Users: " . esc_html($ga4['totalUsers'] ?? 'N/A') . "</li>";
    $message .= "<li>New Users: " . esc_html($ga4['newUsers'] ?? 'N/A') . "</li>";
    $message .= "<li>Sessions: " . esc_html($ga4['sessions'] ?? 'N/A') . "</li>";
    $message .= "<li>Page Views: " . esc_html($ga4['screenPageViews'] ?? 'N/A') . "</li>";
    $message .= "<li>Bounce Rate: " . esc_html($ga4['bounceRate'] ?? 'N/A') . "%</li>";
    $message .= "<li>Engagement Rate: " . esc_html($ga4['engagementRate'] ?? 'N/A') . "%</li>";
    $message .= "</ul>";
  } else {
    $message .= "<p>No analytics data available</p>";
  }
  
  $message .= "
      <hr style='margin: 30px 0; border: none; border-top: 1px solid #eee;'>
      <p style='font-size: 12px; color: #666;'>This support snapshot was generated automatically by Luna Chat AI on " . date('Y-m-d H:i:s T') . "</p>
    </div>
  </body>
  </html>
  ";
  
  $headers = array('Content-Type: text/html; charset=UTF-8');
  return wp_mail($email, $subject, $message, $headers);
}

/**
 * Handles analytics requests and provides GA4 data
 */
function luna_handle_analytics_request($prompt, $facts) {
  $site_url = isset($facts['site_url']) ? $facts['site_url'] : home_url('/');
  $site_name = parse_url($site_url, PHP_URL_HOST);

  // Get GA4 data from facts array (same as intelligence report)
  $ga4_metrics = null;
  $ga4_meta = array(
    'last_synced'    => isset($facts['ga4_last_synced']) ? $facts['ga4_last_synced'] : null,
    'date_range'     => isset($facts['ga4_date_range']) ? $facts['ga4_date_range'] : null,
    'source_url'     => isset($facts['ga4_source_url']) ? $facts['ga4_source_url'] : null,
    'property_id'    => isset($facts['ga4_property_id']) ? $facts['ga4_property_id'] : null,
    'measurement_id' => isset($facts['ga4_measurement_id']) ? $facts['ga4_measurement_id'] : null,
  );

  if (isset($facts['ga4_metrics'])) {
    $ga4_metrics = $facts['ga4_metrics'];
  }

  // Debug logging
  error_log('[Luna Analytics] Facts keys: ' . implode(', ', array_keys($facts)));
  error_log('[Luna Analytics] GA4 metrics found: ' . ($ga4_metrics ? 'YES' : 'NO'));
  if ($ga4_metrics) {
    error_log('[Luna Analytics] GA4 data: ' . print_r($ga4_metrics, true));
  }

  if (!$ga4_metrics) {
    error_log('[Luna Analytics] Attempting to fetch GA4 metrics directly from Hub data streams.');
    $ga4_info = luna_fetch_ga4_metrics_from_hub();
    if ($ga4_info && isset($ga4_info['metrics'])) {
      $ga4_metrics = $ga4_info['metrics'];
      foreach (array('last_synced','date_range','source_url','property_id','measurement_id') as $meta_key) {
        if (isset($ga4_info[$meta_key]) && empty($ga4_meta[$meta_key])) {
          $ga4_meta[$meta_key] = $ga4_info[$meta_key];
        }
      }
      error_log('[Luna Analytics] GA4 metrics hydrated from data streams: ' . print_r($ga4_metrics, true));
    }
  }

  if (!$ga4_metrics) {
    return "I don't have access to your analytics data right now. Your GA4 integration may need to be refreshed. You can check your analytics settings in the Visible Light Hub profile, or I can help you set up Google Analytics if it's not configured yet.";
  }

  $lc = strtolower($prompt);

  // Handle specific analytics questions
  if (preg_match('/\b(page.*views|pageviews)\b/', $lc)) {
    $page_views = isset($ga4_metrics['screenPageViews']) ? $ga4_metrics['screenPageViews'] : 'N/A';
    return "Your page views for the current period are: **" . $page_views . "** views. This data comes from your Google Analytics 4 integration.";
  }

  if (preg_match('/\b(users|visitors)\b/', $lc)) {
    $total_users = isset($ga4_metrics['totalUsers']) ? $ga4_metrics['totalUsers'] : 'N/A';
    $new_users = isset($ga4_metrics['newUsers']) ? $ga4_metrics['newUsers'] : 'N/A';
    return "Your user analytics show:\n• **Total Users**: " . $total_users . "\n• **New Users**: " . $new_users . "\nThis data comes from your Google Analytics 4 integration.";
  }

  if (preg_match('/\b(sessions)\b/', $lc)) {
    $sessions = isset($ga4_metrics['sessions']) ? $ga4_metrics['sessions'] : 'N/A';
    return "Your sessions for the current period are: **" . $sessions . "** sessions. This data comes from your Google Analytics 4 integration.";
  }

  if (preg_match('/\b(bounce.*rate)\b/', $lc)) {
    $bounce_rate = isset($ga4_metrics['bounceRate']) ? $ga4_metrics['bounceRate'] : 'N/A';
    return "Your bounce rate is: **" . $bounce_rate . "%**. This data comes from your Google Analytics 4 integration.";
  }

  if (preg_match('/\b(engagement.*rate|engagement)\b/', $lc)) {
    $engagement_rate = isset($ga4_metrics['engagementRate']) ? $ga4_metrics['engagementRate'] : 'N/A';
    return "Your engagement rate is: **" . $engagement_rate . "%**. This data comes from your Google Analytics 4 integration.";
  }

  if (preg_match('/\b(property\s*id|ga4\s*property)\b/', $lc) && strpos($lc, 'measurement') === false) {
    if (!empty($ga4_meta['property_id'])) {
      return "Your Google Analytics 4 property ID is **" . $ga4_meta['property_id'] . "**.";
    }
    return "I couldn't find a GA4 property ID in your Hub profile. Double-check the Visible Light Hub analytics settings to confirm it's saved.";
  }

  if (preg_match('/measurement\s*id/', $lc)) {
    if (!empty($ga4_meta['measurement_id'])) {
      return "Your GA4 measurement ID is **" . $ga4_meta['measurement_id'] . "**.";
    }
    return "I don't see a GA4 measurement ID recorded yet. Make sure it's configured in your Visible Light Hub analytics settings.";
  }

  if (preg_match('/(last|recent).*(sync|synced|update|updated|refresh)/', $lc)) {
    if (!empty($ga4_meta['last_synced'])) {
      $range_text = '';
      if (!empty($ga4_meta['date_range']) && is_array($ga4_meta['date_range'])) {
        $start = isset($ga4_meta['date_range']['startDate']) ? $ga4_meta['date_range']['startDate'] : '';
        $end   = isset($ga4_meta['date_range']['endDate']) ? $ga4_meta['date_range']['endDate'] : '';
        if ($start || $end) {
          $range_text = ' covering ' . trim($start . ' to ' . $end);
        }
      }
      return "Your GA4 metrics were last synced on **" . $ga4_meta['last_synced'] . "**" . $range_text . ".";
    }
    return "I wasn't able to confirm the last sync time from the Hub profile. Try refreshing the GA4 connection in Visible Light Hub to capture a new sync timestamp.";
  }

  if (preg_match('/(date\s*range|time\s*range|timeframe|time\s*frame|reporting\s*period)/', $lc)) {
    if (!empty($ga4_meta['date_range']) && is_array($ga4_meta['date_range'])) {
      $start = isset($ga4_meta['date_range']['startDate']) ? $ga4_meta['date_range']['startDate'] : 'unknown start';
      $end   = isset($ga4_meta['date_range']['endDate']) ? $ga4_meta['date_range']['endDate'] : 'unknown end';
      return "The current GA4 report covers **" . $start . "** through **" . $end . "**.";
    }
    return "I couldn't determine the reporting range. Try re-syncing GA4 from the Visible Light Hub profile to capture a date window.";
  }

  // General analytics summary
  $summary = "Here's your current analytics data from Google Analytics 4:\n\n";
  $summary .= "📊 **Traffic Overview:**\n";
  $summary .= "• **Total Users**: " . (isset($ga4_metrics['totalUsers']) ? $ga4_metrics['totalUsers'] : 'N/A') . "\n";
  $summary .= "• **New Users**: " . (isset($ga4_metrics['newUsers']) ? $ga4_metrics['newUsers'] : 'N/A') . "\n";
  $summary .= "• **Sessions**: " . (isset($ga4_metrics['sessions']) ? $ga4_metrics['sessions'] : 'N/A') . "\n";
  $summary .= "• **Page Views**: " . (isset($ga4_metrics['screenPageViews']) ? $ga4_metrics['screenPageViews'] : 'N/A') . "\n\n";
  $summary .= "📈 **Engagement Metrics:**\n";
  $summary .= "• **Bounce Rate**: " . (isset($ga4_metrics['bounceRate']) ? $ga4_metrics['bounceRate'] . '%' : 'N/A') . "\n";
  $summary .= "• **Engagement Rate**: " . (isset($ga4_metrics['engagementRate']) ? $ga4_metrics['engagementRate'] . '%' : 'N/A') . "\n";
  $summary .= "• **Avg Session Duration**: " . (isset($ga4_metrics['averageSessionDuration']) ? $ga4_metrics['averageSessionDuration'] : 'N/A') . "\n";

  if (isset($ga4_metrics['totalRevenue']) && $ga4_metrics['totalRevenue'] > 0) {
    $summary .= "• **Revenue**: $" . $ga4_metrics['totalRevenue'] . "\n";
  }

  if (!empty($ga4_meta['property_id'])) {
    $summary .= "• **GA4 Property ID**: " . $ga4_meta['property_id'] . "\n";
  }

  if (!empty($ga4_meta['measurement_id'])) {
    $summary .= "• **Measurement ID**: " . $ga4_meta['measurement_id'] . "\n";
  }

  if (!empty($ga4_meta['last_synced'])) {
    $summary .= "• **Last Synced**: " . $ga4_meta['last_synced'] . "\n";
  }

  if (!empty($ga4_meta['date_range']) && is_array($ga4_meta['date_range'])) {
    $start = isset($ga4_meta['date_range']['startDate']) ? $ga4_meta['date_range']['startDate'] : 'unknown start';
    $end   = isset($ga4_meta['date_range']['endDate']) ? $ga4_meta['date_range']['endDate'] : 'unknown end';
    $summary .= "• **Reporting Range**: " . $start . " → " . $end . "\n";
  }

  $summary .= "\nThis data is pulled from your Google Analytics 4 integration and updated regularly.";

  if (!empty($ga4_meta['source_url'])) {
    $summary .= "\nView more in Google Analytics: " . $ga4_meta['source_url'];
  }

  return $summary;
}

/**
 * Generates a comprehensive web intelligence report using Visible Light Hub data
 */
function luna_generate_web_intelligence_report($facts) {
  $report = array();
  
  // Site Overview
  $site_url = isset($facts['site_url']) ? $facts['site_url'] : home_url('/');
  $site_name = parse_url($site_url, PHP_URL_HOST);
  
  $report[] = "🌐 **WEB INTELLIGENCE REPORT** for " . $site_name;
  $report[] = "Generated: " . date('Y-m-d H:i:s T');
  $report[] = "";
  
  // System Health & Performance
  $report[] = "📊 **SYSTEM HEALTH & PERFORMANCE**";
  $health_score = isset($facts['health_score']) ? $facts['health_score'] : 'N/A';
  $wp_version = isset($facts['wp_version']) ? $facts['wp_version'] : 'Unknown';
  $php_version = isset($facts['php_version']) ? $facts['php_version'] : 'Unknown';
  $memory_usage = isset($facts['memory_usage']) ? $facts['memory_usage'] : 'Unknown';
  
  $report[] = "• Overall Health Score: " . $health_score . "%";
  $report[] = "• WordPress Version: " . $wp_version;
  $report[] = "• PHP Version: " . $php_version;
  $report[] = "• Memory Usage: " . $memory_usage;
  $report[] = "";
  
  // Security Analysis
  $report[] = "🔒 **SECURITY ANALYSIS**";
  $tls_valid = isset($facts['tls_valid']) ? $facts['tls_valid'] : false;
  $tls_issuer = isset($facts['tls_issuer']) ? $facts['tls_issuer'] : 'Unknown';
  $tls_expires = isset($facts['tls_expires']) ? $facts['tls_expires'] : 'Unknown';
  $mfa_status = isset($facts['mfa']) ? $facts['mfa'] : 'Not configured';
  
  $report[] = "• SSL/TLS Status: " . ($tls_valid ? "✅ Active" : "❌ Issues detected");
  $report[] = "• Certificate Issuer: " . $tls_issuer;
  $report[] = "• Certificate Expires: " . $tls_expires;
  $report[] = "• Multi-Factor Auth: " . $mfa_status;
  $report[] = "";
  
  // Analytics & Traffic Intelligence
  $report[] = "📈 **ANALYTICS & TRAFFIC INTELLIGENCE**";
  
  // Check if GA4 data is available
  if (isset($facts['ga4_metrics'])) {
    $ga4 = $facts['ga4_metrics'];
    $report[] = "• Total Users: " . (isset($ga4['totalUsers']) ? $ga4['totalUsers'] : 'N/A');
    $report[] = "• New Users: " . (isset($ga4['newUsers']) ? $ga4['newUsers'] : 'N/A');
    $report[] = "• Sessions: " . (isset($ga4['sessions']) ? $ga4['sessions'] : 'N/A');
    $report[] = "• Page Views: " . (isset($ga4['screenPageViews']) ? $ga4['screenPageViews'] : 'N/A');
    $report[] = "• Bounce Rate: " . (isset($ga4['bounceRate']) ? $ga4['bounceRate'] . '%' : 'N/A');
    $report[] = "• Engagement Rate: " . (isset($ga4['engagementRate']) ? $ga4['engagementRate'] . '%' : 'N/A');
    $report[] = "• Avg Session Duration: " . (isset($ga4['averageSessionDuration']) ? $ga4['averageSessionDuration'] : 'N/A');
    $report[] = "• Total Revenue: " . (isset($ga4['totalRevenue']) ? '$' . $ga4['totalRevenue'] : 'N/A');
  } else {
    $report[] = "• Analytics: GA4 integration not configured or no recent data";
  }
  $report[] = "";
  
  // Content & SEO Intelligence
  $report[] = "📝 **CONTENT & SEO INTELLIGENCE**";
  $theme = isset($facts['theme']) ? $facts['theme'] : 'Unknown';
  $active_plugins = isset($facts['active_plugins']) ? count($facts['active_plugins']) : 0;
  $pages_count = isset($facts['pages_count']) ? $facts['pages_count'] : 'Unknown';
  $posts_count = isset($facts['posts_count']) ? $facts['posts_count'] : 'Unknown';
  
  $report[] = "• Active Theme: " . $theme;
  $report[] = "• Active Plugins: " . $active_plugins;
  $report[] = "• Pages: " . $pages_count;
  $report[] = "• Posts: " . $posts_count;
  $report[] = "";
  
  // Infrastructure Intelligence
  $report[] = "🏗️ **INFRASTRUCTURE INTELLIGENCE**";
  $hosting_provider = isset($facts['hosting_provider']) ? $facts['hosting_provider'] : 'Unknown';
  $server_info = isset($facts['server_info']) ? $facts['server_info'] : 'Unknown';
  $cdn_status = isset($facts['cdn_status']) ? $facts['cdn_status'] : 'Not detected';
  
  $report[] = "• Hosting Provider: " . $hosting_provider;
  $report[] = "• Server Info: " . $server_info;
  $report[] = "• CDN Status: " . $cdn_status;
  $report[] = "";
  
  // Data Streams Intelligence
  $report[] = "🔄 **DATA STREAMS INTELLIGENCE**";
  $streams_count = isset($facts['data_streams_count']) ? $facts['data_streams_count'] : 0;
  $active_streams = isset($facts['active_streams']) ? $facts['active_streams'] : 0;
  $last_sync = isset($facts['last_sync']) ? $facts['last_sync'] : 'Unknown';
  
  $report[] = "• Total Data Streams: " . $streams_count;
  $report[] = "• Active Streams: " . $active_streams;
  $report[] = "• Last Sync: " . $last_sync;
  $report[] = "";
  
  // Recommendations & Insights
  $report[] = "💡 **RECOMMENDATIONS & INSIGHTS**";
  
  // Health-based recommendations
  if (is_numeric($health_score)) {
    if ($health_score >= 90) {
      $report[] = "• ✅ Excellent system health - maintain current practices";
    } elseif ($health_score >= 70) {
      $report[] = "• ⚠️ Good health with room for improvement - consider optimization";
    } else {
      $report[] = "• 🚨 Health score needs attention - review system performance";
    }
  }
  
  // Security recommendations
  if (!$tls_valid) {
    $report[] = "• 🔒 SSL/TLS certificate needs attention";
  }
  
  if ($mfa_status === 'Not configured') {
    $report[] = "• 🔐 Consider implementing Multi-Factor Authentication";
  }
  
  // Analytics recommendations
  if (!isset($facts['ga4_metrics'])) {
    $report[] = "• 📊 Set up Google Analytics 4 for detailed traffic insights";
  }
  
  $report[] = "";
  $report[] = "📋 **REPORT SUMMARY**";
  $report[] = "This intelligence report is generated from your Visible Light Hub data and provides a comprehensive overview of your website's performance, security, and analytics. Use this information to make informed decisions about optimizations and improvements.";
  $report[] = "";
  $report[] = "For detailed analysis of any specific area, ask me about particular aspects like 'security status', 'analytics data', or 'system performance'.";
  
  return implode("\n", $report);
}