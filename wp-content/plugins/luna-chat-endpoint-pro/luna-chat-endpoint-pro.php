<?php
/**
 * Plugin Name: Luna Chat Endpoint Pro v1.1
 * Description: Hub-side REST API endpoints for Luna Chat system. Handles all API requests from client sites.
 * Version:     2.0.0
 * Author:      Visible Light
 * License:     GPLv2 or later
 */

if ( ! defined( 'ABSPATH' ) ) exit;

/* =========================================================================
 * Core Hub Endpoints Only
 * ========================================================================= */

/**
 * Chat endpoint for client sites
 */
add_action('rest_api_init', function () {
  register_rest_route('luna/v1', '/chat-live', [
    'methods' => 'POST',
    'permission_callback' => '__return_true',
    'callback' => function (WP_REST_Request $req) {
      $tenant = $req->get_param('tenant') ?: 'demo';
      $prompt = $req->get_param('prompt') ?: '';
      
      if (empty($prompt)) {
        return new WP_REST_Response(['answer' => 'Please provide a message.'], 400);
      }
      
      // Simple response for Hub
      return new WP_REST_Response([
        'answer' => 'This is a Hub endpoint. Client sites should use their own chat functionality.',
        'sources' => [],
        'actions' => [],
        'confidence' => 0.8,
      ], 200);
    },
  ]);
});

/**
 * Health check endpoint
 */
add_action('rest_api_init', function () {
  register_rest_route('luna/v1', '/health', [
    'methods' => 'GET',
    'permission_callback' => '__return_true',
    'callback' => function (WP_REST_Request $req) {
      return new WP_REST_Response([
        'status' => 'ok',
        'message' => 'Luna Hub endpoints are working',
        'timestamp' => current_time('mysql'),
      ], 200);
    },
  ]);
});

/**
 * Conversations endpoint for client sites to log conversations
 */
add_action('rest_api_init', function () {
  register_rest_route('luna_widget/v1', '/conversations/log', [
    'methods' => 'POST',
    'permission_callback' => '__return_true',
    'callback' => function (WP_REST_Request $req) {
      $license = $req->get_header('X-Luna-License') ?: $req->get_param('license');
      if (!$license) {
        return new WP_REST_Response(['error' => 'License required'], 401);
      }
      
      $conversation_data = $req->get_json_params();
      if (!$conversation_data) {
        return new WP_REST_Response(['error' => 'Invalid conversation data'], 400);
      }
      
      // Store conversation in Hub
      $conversations = get_option('vl_hub_conversations', []);
      if (!is_array($conversations)) $conversations = [];
      
      $conversation_id = $conversation_data['id'] ?? uniqid('conv_');
      $conversations[$conversation_id] = [
        'license' => $license,
        'site' => home_url(),
        'started_at' => $conversation_data['started_at'] ?? current_time('mysql'),
        'transcript' => $conversation_data['transcript'] ?? [],
        'logged_at' => current_time('mysql'),
      ];
      
      update_option('vl_hub_conversations', $conversations);
      
      return new WP_REST_Response(['ok' => true, 'id' => $conversation_id], 200);
    }
  ]);
});

/**
 * System comprehensive endpoint for client sites (GET to fetch, POST to store)
 */
add_action('rest_api_init', function () {
  register_rest_route('luna_widget/v1', '/system/comprehensive', [
    'methods' => ['GET', 'POST'],
    'permission_callback' => '__return_true',
    'callback' => function (WP_REST_Request $req) {
      $license = $req->get_header('X-Luna-License') ?: $req->get_param('license');
      if (!$license) {
        return new WP_REST_Response(['error' => 'License required'], 401);
      }

      // Find the license ID from the license key
      $licenses = get_option('vl_licenses_registry', []);
      $license_id = null;
      foreach ($licenses as $id => $lic) {
        if ($lic['key'] === $license) {
          $license_id = $id;
          break;
        }
      }

      if (!$license_id) {
        return new WP_REST_Response(['error' => 'License not found'], 404);
      }

      // Handle POST (store data from client)
      if ($req->get_method() === 'POST') {
        $comprehensive_data = $req->get_json_params();
        if (!$comprehensive_data) {
          return new WP_REST_Response(['error' => 'Invalid comprehensive data'], 400);
        }

        // Store comprehensive data in Hub profiles
        $profiles = get_option('vl_hub_profiles', []);
        if (!isset($profiles[$license_id])) {
          $profiles[$license_id] = [];
        }

        // Update with comprehensive data
        $profiles[$license_id] = array_merge($profiles[$license_id], $comprehensive_data);
        $profiles[$license_id]['last_updated'] = current_time('mysql');

        update_option('vl_hub_profiles', $profiles);

        error_log('[Luna Hub] Stored comprehensive data for license_id: ' . $license_id);

        return new WP_REST_Response(['ok' => true, 'message' => 'Comprehensive data stored'], 200);
      }

      // Handle GET (return data to client)
      $profile = vl_hub_profile_resolve($license, ['force_refresh' => (bool) $req->get_param('refresh')]);
      if (is_wp_error($profile)) {
        $status = (int) ($profile->get_error_data('status') ?? 500);
        return new WP_REST_Response(['error' => $profile->get_error_message()], $status);
      }

      return new WP_REST_Response($profile, 200);
    }
  ]);
});

/**
 * Security data endpoint for client sites
 */
add_action('rest_api_init', function () {
  register_rest_route('vl-hub/v1', '/profile/security', [
    'methods' => 'POST',
    'permission_callback' => '__return_true',
    'callback' => function (WP_REST_Request $req) {
      $license = $req->get_header('X-Luna-License') ?: $req->get_param('license');
      if (!$license) {
        return new WP_REST_Response(['error' => 'License required'], 401);
      }
      
      $request_data = $req->get_json_params();
      if (!$request_data) {
        return new WP_REST_Response(['error' => 'Invalid security data'], 400);
      }
      
      // Extract security data from the payload
      $security_data = isset($request_data['security']) ? $request_data['security'] : $request_data;
      
      // Debug logging
      error_log('[Luna Hub] Security data received for license: ' . substr($license, 0, 8) . '...');
      error_log('[Luna Hub] Security data: ' . print_r($security_data, true));
      
      // Find the license ID from the license key
      $licenses = get_option('vl_licenses_registry', []);
      $license_id = null;
      foreach ($licenses as $id => $lic) {
        if ($lic['key'] === $license) {
          $license_id = $id;
          break;
        }
      }
      
      if (!$license_id) {
        return new WP_REST_Response(['error' => 'License not found'], 404);
      }
      
      // Store security data in Hub profiles
      $profiles = get_option('vl_hub_profiles', []);
      if (!isset($profiles[$license_id])) {
        $profiles[$license_id] = [];
      }
      
      $profiles[$license_id]['security'] = $security_data;
      $profiles[$license_id]['last_updated'] = current_time('mysql');
      
      update_option('vl_hub_profiles', $profiles);
      
      // Debug: Log what was stored
      error_log('[Luna Hub] Stored security data for license_id: ' . $license_id);
      error_log('[Luna Hub] Stored data: ' . print_r($security_data, true));
      
      return new WP_REST_Response(['ok' => true, 'message' => 'Security data stored'], 200);
    }
  ]);
});

/* =========================================================================
 * Hub profile utilities
 * ========================================================================= */

/**
 * Resolve a license key to its registry record.
 */
function vl_hub_find_license_record(string $license_key): array {
  $licenses = get_option('vl_licenses_registry', []);
  foreach ($licenses as $id => $row) {
    if (isset($row['key']) && hash_equals((string) $row['key'], $license_key)) {
      return ['id' => $id, 'record' => is_array($row) ? $row : [], 'license' => $license_key];
    }
  }

  return [];
}

/**
 * Determine whether a stored profile is missing WordPress inventory details.
 */
function vl_hub_profile_missing_inventory(array $profile): bool {
  $required_arrays = ['posts', 'pages', 'plugins', 'themes', 'users'];
  foreach ($required_arrays as $key) {
    if (!array_key_exists($key, $profile) || !is_array($profile[$key])) {
      return true;
    }
  }

  return false;
}

/**
 * Fetch a remote endpoint from a client site with the given license header.
 */
function vl_hub_fetch_client_endpoint(string $site_url, string $path, string $license_key, array $query = []) {
  $site_url = trim($site_url);
  if ($site_url === '') {
    return null;
  }

  $base = rtrim($site_url, '/');
  $url  = $base . $path;
  if ($query) {
    $url = add_query_arg($query, $url);
  }

  $response = wp_remote_get($url, [
    'timeout'   => 15,
    'headers'   => [
      'X-Luna-License' => $license_key,
      'Accept'         => 'application/json',
    ],
    'sslverify' => false,
  ]);

  if (is_wp_error($response)) {
    error_log('[Luna Hub] Failed to fetch client endpoint ' . $url . ': ' . $response->get_error_message());
    return null;
  }

  $code = (int) wp_remote_retrieve_response_code($response);
  if ($code < 200 || $code >= 300) {
    error_log('[Luna Hub] HTTP ' . $code . ' fetching client endpoint ' . $url);
    return null;
  }

  $body = json_decode(wp_remote_retrieve_body($response), true);
  if (!is_array($body)) {
    error_log('[Luna Hub] Invalid JSON from client endpoint ' . $url);
    return null;
  }

  return $body;
}

/**
 * Refresh the stored profile for a license by querying the client site directly.
 */
function vl_hub_refresh_profile_from_client(array $license_info, array $profile = []): array {
  $license_key   = $license_info['license'];
  $license_id    = $license_info['id'];
  $license_record= $license_info['record'];
  $site_url      = isset($license_record['site']) ? (string) $license_record['site'] : '';

  if ($site_url === '') {
    return $profile;
  }

  if (!is_array($profile)) {
    $profile = [];
  }

  // System snapshot (site + WordPress + plugins/themes overview)
  $system_snapshot = vl_hub_fetch_client_endpoint($site_url, '/wp-json/luna_widget/v1/system/site', $license_key);
  if (is_array($system_snapshot)) {
    if (isset($system_snapshot['site']) && is_array($system_snapshot['site'])) {
      $profile['site'] = $system_snapshot['site'];
    }
    if (isset($system_snapshot['wordpress']) && is_array($system_snapshot['wordpress'])) {
      $profile['wordpress'] = $system_snapshot['wordpress'];
    }
    if (isset($system_snapshot['plugins']) && is_array($system_snapshot['plugins'])) {
      $profile['plugins'] = $system_snapshot['plugins'];
    }
    if (isset($system_snapshot['themes']) && is_array($system_snapshot['themes'])) {
      $profile['themes'] = $system_snapshot['themes'];
    }
  }

  // Detailed plugin inventory
  $plugins_response = vl_hub_fetch_client_endpoint($site_url, '/wp-json/luna_widget/v1/plugins', $license_key);
  if (is_array($plugins_response) && isset($plugins_response['items']) && is_array($plugins_response['items'])) {
    $profile['plugins'] = $plugins_response['items'];
  }

  // Detailed theme inventory
  $themes_response = vl_hub_fetch_client_endpoint($site_url, '/wp-json/luna_widget/v1/themes', $license_key);
  if (is_array($themes_response) && isset($themes_response['items']) && is_array($themes_response['items'])) {
    $profile['themes'] = $themes_response['items'];
  }

  // Posts and pages
  $posts_response = vl_hub_fetch_client_endpoint($site_url, '/wp-json/luna_widget/v1/content/posts', $license_key, ['per_page' => 100]);
  if (is_array($posts_response)) {
    $profile['posts'] = isset($posts_response['items']) && is_array($posts_response['items']) ? $posts_response['items'] : [];
    if (!isset($profile['content']) || !is_array($profile['content'])) {
      $profile['content'] = [];
    }
    if (isset($posts_response['total'])) {
      $profile['content']['posts_total'] = (int) $posts_response['total'];
    }
  }

  $pages_response = vl_hub_fetch_client_endpoint($site_url, '/wp-json/luna_widget/v1/content/pages', $license_key, ['per_page' => 100]);
  if (is_array($pages_response)) {
    $profile['pages'] = isset($pages_response['items']) && is_array($pages_response['items']) ? $pages_response['items'] : [];
    if (!isset($profile['content']) || !is_array($profile['content'])) {
      $profile['content'] = [];
    }
    if (isset($pages_response['total'])) {
      $profile['content']['pages_total'] = (int) $pages_response['total'];
    }
  }

  // Users roster
  $users_response = vl_hub_fetch_client_endpoint($site_url, '/wp-json/luna_widget/v1/users', $license_key, ['per_page' => 100]);
  if (is_array($users_response)) {
    $profile['users'] = isset($users_response['items']) && is_array($users_response['items']) ? $users_response['items'] : [];
    if (isset($users_response['total'])) {
      $profile['users_total'] = (int) $users_response['total'];
    }
  }

  // Populate counts
  $posts_total  = isset($profile['content']['posts_total']) ? (int) $profile['content']['posts_total'] : (is_array($profile['posts'] ?? null) ? count($profile['posts']) : 0);
  $pages_total  = isset($profile['content']['pages_total']) ? (int) $profile['content']['pages_total'] : (is_array($profile['pages'] ?? null) ? count($profile['pages']) : 0);
  $users_total  = isset($profile['users_total']) ? (int) $profile['users_total'] : (is_array($profile['users'] ?? null) ? count($profile['users']) : 0);
  $plugins_total= is_array($profile['plugins'] ?? null) ? count($profile['plugins']) : 0;

  $profile['counts'] = [
    'posts'   => $posts_total,
    'pages'   => $pages_total,
    'users'   => $users_total,
    'plugins' => $plugins_total,
  ];

  // Maintain legacy underscore keys expected by some consumers
  $profile['_posts'] = $profile['posts'] ?? [];
  $profile['_pages'] = $profile['pages'] ?? [];
  $profile['_users'] = $profile['users'] ?? [];

  // Ensure base metadata is available
  $home_url = $profile['site']['home_url'] ?? ($license_record['site'] ?? '');
  if ($home_url) {
    $profile['home_url'] = $home_url;
  }
  if (!isset($profile['https'])) {
    if (isset($profile['site']['https'])) {
      $profile['https'] = (bool) $profile['site']['https'];
    } elseif ($home_url) {
      $profile['https'] = (stripos($home_url, 'https://') === 0);
    }
  }

  $profile['license_id']   = $license_id;
  $profile['license_key']  = $license_key;
  if (!isset($profile['client_name']) && !empty($license_record['client'])) {
    $profile['client_name'] = $license_record['client'];
  }

  $profile['profile_last_synced'] = current_time('mysql');

  return $profile;
}

/**
 * Resolve and optionally refresh the stored profile for a license key.
 */
function vl_hub_profile_resolve(string $license_key, array $options = []) {
  $license_info = vl_hub_find_license_record($license_key);
  if (!$license_info) {
    return new WP_Error('license_not_found', __('License not found', 'visible-light'), ['status' => 404]);
  }

  $profiles = get_option('vl_hub_profiles', []);
  $stored   = isset($profiles[$license_info['id']]) && is_array($profiles[$license_info['id']]) ? $profiles[$license_info['id']] : [];

  $force_refresh = !empty($options['force_refresh']);
  if ($force_refresh || vl_hub_profile_missing_inventory($stored)) {
    $stored = vl_hub_refresh_profile_from_client($license_info, $stored);
    $profiles[$license_info['id']] = $stored;
    update_option('vl_hub_profiles', $profiles);
  }

  if (!is_array($stored)) {
    $stored = [];
  }

  if (empty($stored)) {
    $home_url = isset($license_info['record']['site']) ? (string) $license_info['record']['site'] : '';
    $stored = [
      'site'    => ['home_url' => $home_url, 'https' => stripos($home_url, 'https://') === 0],
      'posts'   => [],
      'pages'   => [],
      'plugins' => [],
      'themes'  => [],
      'users'   => [],
      'content' => [],
    ];
  }

  if (!isset($stored['posts']) && isset($stored['_posts']) && is_array($stored['_posts'])) {
    $stored['posts'] = $stored['_posts'];
  }
  if (!isset($stored['pages']) && isset($stored['_pages']) && is_array($stored['_pages'])) {
    $stored['pages'] = $stored['_pages'];
  }
  if (!isset($stored['users']) && isset($stored['_users']) && is_array($stored['_users'])) {
    $stored['users'] = $stored['_users'];
  }

  if (!isset($stored['license_id'])) {
    $stored['license_id'] = $license_info['id'];
  }
  if (!isset($stored['license_key'])) {
    $stored['license_key'] = $license_key;
  }
  if (!isset($stored['client_name']) && !empty($license_info['record']['client'])) {
    $stored['client_name'] = $license_info['record']['client'];
  }

  if (!isset($stored['home_url'])) {
    $stored['home_url'] = $stored['site']['home_url'] ?? ($license_info['record']['site'] ?? '');
  }
  if (!isset($stored['https'])) {
    if (isset($stored['site']['https'])) {
      $stored['https'] = (bool) $stored['site']['https'];
    } elseif (!empty($stored['home_url'])) {
      $stored['https'] = stripos($stored['home_url'], 'https://') === 0;
    }
  }

  if (!isset($stored['counts']) || !is_array($stored['counts'])) {
    $stored['counts'] = [];
  }
  $stored['counts']['posts'] = isset($stored['content']['posts_total']) ? (int) $stored['content']['posts_total'] : (is_array($stored['posts'] ?? null) ? count($stored['posts']) : 0);
  $stored['counts']['pages'] = isset($stored['content']['pages_total']) ? (int) $stored['content']['pages_total'] : (is_array($stored['pages'] ?? null) ? count($stored['pages']) : 0);
  $stored['counts']['users'] = isset($stored['users_total']) ? (int) $stored['users_total'] : (is_array($stored['users'] ?? null) ? count($stored['users']) : 0);
  $stored['counts']['plugins'] = is_array($stored['plugins'] ?? null) ? count($stored['plugins']) : 0;

  if (!isset($stored['profile_last_synced'])) {
    $stored['profile_last_synced'] = current_time('mysql');
  }

  return $stored;
}

/* =========================================================================
 * VL Hub profile endpoint
 * ========================================================================= */

add_action('rest_api_init', function () {
  register_rest_route('vl-hub/v1', '/profile', [
    'methods' => ['GET', 'POST'],
    'permission_callback' => '__return_true',
    'callback' => function (WP_REST_Request $req) {
      $license = $req->get_header('X-Luna-License') ?: $req->get_param('license');
      if (!$license) {
        return new WP_REST_Response(['error' => 'License required'], 401);
      }

      if ($req->get_method() === 'POST') {
        $license_info = vl_hub_find_license_record($license);
        if (!$license_info) {
          return new WP_REST_Response(['error' => 'License not found'], 404);
        }

        $payload = $req->get_json_params();
        if (!is_array($payload)) {
          return new WP_REST_Response(['error' => 'Invalid profile payload'], 400);
        }

        $profiles = get_option('vl_hub_profiles', []);
        $current  = isset($profiles[$license_info['id']]) && is_array($profiles[$license_info['id']]) ? $profiles[$license_info['id']] : [];
        $profiles[$license_info['id']] = array_merge($current, $payload, [
          'license_id'          => $license_info['id'],
          'license_key'         => $license,
          'profile_last_synced' => current_time('mysql'),
        ]);
        update_option('vl_hub_profiles', $profiles);

        return new WP_REST_Response(['ok' => true, 'message' => 'Profile stored'], 200);
      }

      $profile = vl_hub_profile_resolve($license, ['force_refresh' => (bool) $req->get_param('refresh')]);
      if (is_wp_error($profile)) {
        $status = (int) ($profile->get_error_data('status') ?? 500);
        return new WP_REST_Response(['error' => $profile->get_error_message()], $status);
      }

      return new WP_REST_Response($profile, 200);
    },
  ]);
});

/**
 * Session start endpoint
 */
add_action('rest_api_init', function () {
  register_rest_route('luna_widget/v1', '/chat/session-start', [
    'methods' => 'POST',
    'permission_callback' => '__return_true',
    'callback' => function (WP_REST_Request $req) {
      $license = $req->get_header('X-Luna-License') ?: $req->get_param('license');
      if (!$license) {
        return new WP_REST_Response(['error' => 'License required'], 401);
      }
      
      $data = $req->get_json_params();
      if (!$data || !isset($data['session_id'])) {
        return new WP_REST_Response(['error' => 'Session ID required'], 400);
      }
      
      // Find the license ID from the license key
      $licenses = get_option('vl_licenses_registry', []);
      $license_id = null;
      foreach ($licenses as $id => $lic) {
        if ($lic['key'] === $license) {
          $license_id = $id;
          break;
        }
      }
      
      if (!$license_id) {
        return new WP_REST_Response(['error' => 'License not found'], 404);
      }
      
      // Store session start data
      $session_starts = get_option('vl_hub_session_starts', []);
      if (!isset($session_starts[$license_id])) {
        $session_starts[$license_id] = [];
      }
      
      $session_starts[$license_id][] = [
        'session_id' => $data['session_id'],
        'started_at' => $data['started_at'] ?? current_time('mysql'),
        'timestamp' => time()
      ];
      
      update_option('vl_hub_session_starts', $session_starts);
      
      error_log('[Luna Hub] Session started for license_id: ' . $license_id . ', session: ' . $data['session_id']);
      
      return new WP_REST_Response(['ok' => true, 'message' => 'Session start recorded'], 200);
    }
  ]);
});

/**
 * Session end endpoint
 */
add_action('rest_api_init', function () {
  register_rest_route('luna_widget/v1', '/chat/session-end', [
    'methods' => 'POST',
    'permission_callback' => '__return_true',
    'callback' => function (WP_REST_Request $req) {
      $license = $req->get_header('X-Luna-License') ?: $req->get_param('license');
      if (!$license) {
        return new WP_REST_Response(['error' => 'License required'], 401);
      }
      
      $data = $req->get_json_params();
      if (!$data || !isset($data['session_id'])) {
        return new WP_REST_Response(['error' => 'Session ID required'], 400);
      }
      
      // Find the license ID from the license key
      $licenses = get_option('vl_licenses_registry', []);
      $license_id = null;
      foreach ($licenses as $id => $lic) {
        if ($lic['key'] === $license) {
          $license_id = $id;
          break;
        }
      }
      
      if (!$license_id) {
        return new WP_REST_Response(['error' => 'License not found'], 404);
      }
      
      // Store session end data
      $session_ends = get_option('vl_hub_session_ends', []);
      if (!isset($session_ends[$license_id])) {
        $session_ends[$license_id] = [];
      }
      
      $session_ends[$license_id][] = [
        'session_id' => $data['session_id'],
        'reason' => $data['reason'] ?? 'unknown',
        'ended_at' => $data['ended_at'] ?? current_time('mysql'),
        'timestamp' => time()
      ];
      
      update_option('vl_hub_session_ends', $session_ends);
      
      error_log('[Luna Hub] Session ended for license_id: ' . $license_id . ', session: ' . $data['session_id'] . ', reason: ' . ($data['reason'] ?? 'unknown'));
      
      return new WP_REST_Response(['ok' => true, 'message' => 'Session end recorded'], 200);
    }
  ]);
});

/**
 * Conversation logging endpoint
 */
add_action('rest_api_init', function () {
  register_rest_route('luna_widget/v1', '/conversations/log', [
    'methods' => 'POST',
    'permission_callback' => '__return_true',
    'callback' => function (WP_REST_Request $req) {
      $license = $req->get_header('X-Luna-License') ?: $req->get_param('license');
      if (!$license) {
        return new WP_REST_Response(['error' => 'License required'], 401);
      }
      
      $conversation_data = $req->get_json_params();
      if (!$conversation_data) {
        return new WP_REST_Response(['error' => 'Invalid conversation data'], 400);
      }
      
      // Find the license ID from the license key
      $licenses = get_option('vl_licenses_registry', []);
      $license_id = null;
      foreach ($licenses as $id => $lic) {
        if ($lic['key'] === $license) {
          $license_id = $id;
          break;
        }
      }
      
      if (!$license_id) {
        return new WP_REST_Response(['error' => 'License not found'], 404);
      }
      
      // Store conversation data
      $conversations = get_option('vl_hub_conversations', []);
      if (!isset($conversations[$license_id])) {
        $conversations[$license_id] = [];
      }
      
      $conversations[$license_id][] = [
        'id' => $conversation_data['id'] ?? 'conv_' . uniqid('', true),
        'started_at' => $conversation_data['started_at'] ?? current_time('mysql'),
        'transcript' => $conversation_data['transcript'] ?? [],
        'received_at' => current_time('mysql'),
        'timestamp' => time()
      ];
      
      update_option('vl_hub_conversations', $conversations);
      
      error_log('[Luna Hub] Conversation logged for license_id: ' . $license_id . ', conv_id: ' . ($conversation_data['id'] ?? 'unknown'));

      return new WP_REST_Response(['ok' => true, 'message' => 'Conversation logged'], 200);
    }
  ]);
});

/* =========================================================================
 * AI Constellation dataset endpoint
 * ========================================================================= */

add_action('rest_api_init', function () {
  register_rest_route('vl-hub/v1', '/constellation', [
    'methods'  => 'GET',
    'permission_callback' => '__return_true',
    'callback' => 'vl_rest_constellation_dataset',
    'args'     => [
      'license' => [
        'type' => 'string',
        'required' => false,
      ],
    ],
  ]);
});

/**
 * Build a constellation dataset representing Hub + widget telemetry.
 */
function vl_rest_constellation_dataset(WP_REST_Request $req): WP_REST_Response {
  $license_filter = trim((string)$req->get_param('license'));
  $data = vl_constellation_build_dataset($license_filter);
  return new WP_REST_Response($data, 200);
}

/**
 * Assemble constellation data for all licenses or a single filtered license.
 */
function vl_constellation_build_dataset(string $license_filter = ''): array {
  $licenses      = get_option('vl_licenses_registry', []);
  $profiles      = get_option('vl_hub_profiles', []);
  $conversations = get_option('vl_hub_conversations', []);
  $session_starts = get_option('vl_hub_session_starts', []);
  $session_ends   = get_option('vl_hub_session_ends', []);
  $connections    = get_option('vl_client_connections', []);

  $clients = [];
  foreach ($licenses as $license_id => $row) {
    if ($license_filter !== '') {
      $matches = false;
      if (stripos($license_id, $license_filter) !== false) {
        $matches = true;
      } elseif (!empty($row['key']) && stripos((string)$row['key'], $license_filter) !== false) {
        $matches = true;
      } elseif (!empty($row['client']) && stripos((string)$row['client'], $license_filter) !== false) {
        $matches = true;
      }
      if (!$matches) {
        continue;
      }
    }

    $profile   = is_array($profiles[$license_id] ?? null) ? $profiles[$license_id] : [];
    $client_ds = vl_constellation_build_client(
      (string)$license_id,
      is_array($row) ? $row : [],
      $profile,
      is_array($conversations[$license_id] ?? null) ? $conversations[$license_id] : [],
      is_array($session_starts[$license_id] ?? null) ? $session_starts[$license_id] : [],
      is_array($session_ends[$license_id] ?? null) ? $session_ends[$license_id] : [],
      is_array($connections[$license_id] ?? null) ? $connections[$license_id] : []
    );

    $clients[] = $client_ds;
  }

  usort($clients, function ($a, $b) {
    return strcasecmp($a['client'], $b['client']);
  });

  return [
    'generated_at'  => current_time('mysql'),
    'total_clients' => count($clients),
    'clients'       => $clients,
  ];
}

/**
 * Build the constellation node map for an individual client license.
 */
function vl_constellation_build_client(string $license_id, array $license_row, array $profile, array $conversations, array $session_starts, array $session_ends, array $connections): array {
  $palette = [
    'identity'       => '#7ee787',
    'infrastructure' => '#58a6ff',
    'security'       => '#f85149',
    'content'        => '#f2cc60',
    'plugins'        => '#d2a8ff',
    'themes'         => '#8b949e',
    'users'          => '#79c0ff',
    'ai'             => '#bc8cff',
    'sessions'       => '#56d364',
    'integrations'   => '#ffa657',
  ];

  $icons = [
    'identity'       => 'visiblelightailogoonly.svg',
    'infrastructure' => 'arrows-rotate-reverse-regular-full.svg',
    'security'       => 'eye-slash-light-full.svg',
    'content'        => 'play-regular-full.svg',
    'plugins'        => 'plus-solid-full.svg',
    'themes'         => 'visiblelightailogo.svg',
    'users'          => 'eye-regular-full.svg',
    'ai'             => 'visiblelightailogo.svg',
    'sessions'       => 'arrows-rotate-reverse-regular-full.svg',
    'integrations'   => 'minus-solid-full.svg',
  ];

  $client = [
    'license_id'   => $license_id,
    'license_key'  => vl_constellation_redact_key($license_row['key'] ?? ''),
    'client'       => vl_constellation_string($license_row['client'] ?? 'Unassigned Client'),
    'site'         => vl_constellation_string($license_row['site'] ?? ''),
    'active'       => !empty($license_row['active']),
    'created'      => vl_constellation_date($license_row['created'] ?? 0),
    'last_seen'    => vl_constellation_date($license_row['last_seen'] ?? 0),
    'categories'   => [],
  ];

  $client['categories'][] = vl_constellation_identity_category($palette['identity'], $icons['identity'], $license_row, $profile);
  $client['categories'][] = vl_constellation_infrastructure_category($palette['infrastructure'], $icons['infrastructure'], $license_row, $profile);
  $client['categories'][] = vl_constellation_security_category($palette['security'], $icons['security'], $profile);
  $client['categories'][] = vl_constellation_content_category($palette['content'], $icons['content'], $profile);
  $client['categories'][] = vl_constellation_plugins_category($palette['plugins'], $icons['plugins'], $profile);
  $client['categories'][] = vl_constellation_theme_category($palette['themes'], $icons['themes'], $profile);
  $client['categories'][] = vl_constellation_users_category($palette['users'], $icons['users'], $profile);
  $client['categories'][] = vl_constellation_ai_category($palette['ai'], $icons['ai'], $conversations);
  $client['categories'][] = vl_constellation_sessions_category($palette['sessions'], $icons['sessions'], $session_starts, $session_ends);
  $client['categories'][] = vl_constellation_integrations_category($palette['integrations'], $icons['integrations'], $connections);

  return $client;
}

function vl_constellation_identity_category(string $color, string $icon, array $license_row, array $profile): array {
  $nodes = [];
  $nodes[] = vl_constellation_node('client', 'Client', $color, 6, vl_constellation_string($license_row['client'] ?? 'Unassigned'));
  $nodes[] = vl_constellation_node('site', 'Primary Site', $color, 6, vl_constellation_string($license_row['site'] ?? ($profile['site'] ?? 'Unknown')));
  $nodes[] = vl_constellation_node('status', 'License Status', $color, !empty($license_row['active']) ? 8 : 4, !empty($license_row['active']) ? 'Active' : 'Inactive');
  $nodes[] = vl_constellation_node('heartbeat', 'Last Heartbeat', $color, 5, vl_constellation_time_ago($license_row['last_seen'] ?? 0));
  if (!empty($license_row['plugin_version'])) {
    $nodes[] = vl_constellation_node('widget_version', 'Widget Version', $color, 5, 'v' . vl_constellation_string($license_row['plugin_version']));
  } elseif (!empty($profile['wordpress']['version'])) {
    $nodes[] = vl_constellation_node('wordpress_version', 'WordPress Version', $color, 4, 'v' . vl_constellation_string($profile['wordpress']['version']));
  }

  return vl_constellation_category('identity', 'Identity & Licensing', $color, $icon, $nodes);
}

function vl_constellation_infrastructure_category(string $color, string $icon, array $license_row, array $profile): array {
  $nodes = [];
  $https = isset($profile['https']) ? (bool)$profile['https'] : null;
  $nodes[] = vl_constellation_node('https', 'HTTPS', $color, $https ? 7 : 4, $https === null ? 'Unknown' : ($https ? 'Secured' : 'Not secure'));

  $wp_version = $profile['wordpress']['version'] ?? ($license_row['wp_version'] ?? '');
  if ($wp_version) {
    $nodes[] = vl_constellation_node('wp_version', 'WordPress Core', $color, 5, 'v' . vl_constellation_string($wp_version));
  }

  $theme_name = $profile['wordpress']['theme']['name'] ?? '';
  if ($theme_name) {
    $nodes[] = vl_constellation_node('theme', 'Active Theme', $color, 5, vl_constellation_string($theme_name));
  }

  $plugin_count = is_array($profile['plugins'] ?? null) ? count($profile['plugins']) : 0;
  if ($plugin_count) {
    $nodes[] = vl_constellation_node('plugin_count', 'Plugins Installed', $color, min(10, max(3, $plugin_count)), $plugin_count . ' plugins');
  }

  $connections = is_array($profile['connections'] ?? null) ? $profile['connections'] : [];
  if ($connections) {
    $nodes[] = vl_constellation_node('connections', 'Remote Connections', $color, min(10, count($connections) + 3), count($connections) . ' integrations');
  }

  if (!$nodes) {
    $nodes[] = vl_constellation_node('infrastructure_placeholder', 'Infrastructure', $color, 3, 'Awaiting telemetry');
  }

  return vl_constellation_category('infrastructure', 'Infrastructure & Platform', $color, $icon, $nodes);
}

function vl_constellation_security_category(string $color, string $icon, array $profile): array {
  $nodes = [];
  $security = is_array($profile['security'] ?? null) ? $profile['security'] : [];
  if ($security) {
    foreach (vl_constellation_flatten_security($security) as $row) {
      $nodes[] = vl_constellation_node($row['id'], $row['label'], $color, $row['value'], $row['detail']);
    }
  }

  if (!$nodes) {
    $nodes[] = vl_constellation_node('security_placeholder', 'Security Signals', $color, 3, 'No security data reported');
  }

  return vl_constellation_category('security', 'Security & Compliance', $color, $icon, $nodes);
}

function vl_constellation_content_category(string $color, string $icon, array $profile): array {
  $nodes = [];
  $posts = is_array($profile['_posts'] ?? null) ? count($profile['_posts']) : (is_array($profile['posts'] ?? null) ? count($profile['posts']) : 0);
  $pages = is_array($profile['_pages'] ?? null) ? count($profile['_pages']) : 0;
  $media = is_array($profile['content']['media'] ?? null) ? count($profile['content']['media']) : 0;

  if ($posts) {
    $nodes[] = vl_constellation_node('posts', 'Published Posts', $color, min(10, max(3, $posts)), $posts . ' posts');
  }
  if ($pages) {
    $nodes[] = vl_constellation_node('pages', 'Published Pages', $color, min(9, max(3, $pages)), $pages . ' pages');
  }
  if ($media) {
    $nodes[] = vl_constellation_node('media', 'Media Items', $color, min(8, max(3, $media)), $media . ' assets');
  }

  if (!$nodes) {
    $nodes[] = vl_constellation_node('content_placeholder', 'Content Footprint', $color, 3, 'Content metrics not synced yet');
  }

  return vl_constellation_category('content', 'Content Universe', $color, $icon, $nodes);
}

function vl_constellation_plugins_category(string $color, string $icon, array $profile): array {
  $nodes = [];
  $plugins = is_array($profile['plugins'] ?? null) ? $profile['plugins'] : [];

  $active = 0;
  foreach ($plugins as $plugin) {
    if (is_array($plugin) && !empty($plugin['is_active'])) {
      $active++;
    } elseif (is_array($plugin) && isset($plugin['status']) && stripos((string)$plugin['status'], 'active') !== false) {
      $active++;
    }
  }

  if ($plugins) {
    $nodes[] = vl_constellation_node('plugins_total', 'Installed Plugins', $color, min(10, max(3, count($plugins))), count($plugins) . ' total');
    $nodes[] = vl_constellation_node('plugins_active', 'Active Plugins', $color, min(10, max(3, $active)), $active . ' active');

    $top = array_slice($plugins, 0, 5);
    foreach ($top as $index => $plugin) {
      $label = vl_constellation_string($plugin['name'] ?? ($plugin['Name'] ?? 'Plugin ' . ($index + 1)));
      $version = vl_constellation_string($plugin['version'] ?? ($plugin['Version'] ?? ''));
      $detail = $version ? 'v' . $version : 'Version unknown';
      $nodes[] = vl_constellation_node('plugin_' . $index, $label, $color, 4, $detail);
    }
  }

  if (!$nodes) {
    $nodes[] = vl_constellation_node('plugins_placeholder', 'Plugins', $color, 3, 'Plugins not reported');
  }

  return vl_constellation_category('plugins', 'Plugin Ecosystem', $color, $icon, $nodes);
}

function vl_constellation_theme_category(string $color, string $icon, array $profile): array {
  $nodes = [];
  $theme = is_array($profile['wordpress']['theme'] ?? null) ? $profile['wordpress']['theme'] : [];
  if ($theme) {
    $nodes[] = vl_constellation_node('theme_name', 'Theme Name', $color, 6, vl_constellation_string($theme['name'] ?? 'Theme'));
    if (!empty($theme['version'])) {
      $nodes[] = vl_constellation_node('theme_version', 'Theme Version', $color, 4, 'v' . vl_constellation_string($theme['version']));
    }
    $nodes[] = vl_constellation_node('theme_status', 'Active', $color, !empty($theme['is_active']) ? 6 : 3, !empty($theme['is_active']) ? 'Active' : 'Inactive');
  }

  $themes = is_array($profile['themes'] ?? null) ? $profile['themes'] : [];
  if ($themes) {
    $nodes[] = vl_constellation_node('themes_total', 'Available Themes', $color, min(8, max(3, count($themes))), count($themes) . ' themes');
  }

  if (!$nodes) {
    $nodes[] = vl_constellation_node('themes_placeholder', 'Themes', $color, 3, 'Theme data not synced');
  }

  return vl_constellation_category('themes', 'Theme & Experience', $color, $icon, $nodes);
}

function vl_constellation_users_category(string $color, string $icon, array $profile): array {
  $nodes = [];
  $users = is_array($profile['users'] ?? null) ? $profile['users'] : (is_array($profile['_users'] ?? null) ? $profile['_users'] : []);

  if ($users) {
    $nodes[] = vl_constellation_node('users_total', 'User Accounts', $color, min(9, max(3, count($users))), count($users) . ' users');
    $roles = [];
    foreach ($users as $user) {
      if (!is_array($user)) continue;
      $role = $user['role'] ?? ($user['roles'][0] ?? 'user');
      $role = is_array($role) ? ($role[0] ?? 'user') : $role;
      $role = strtolower((string)$role);
      $roles[$role] = ($roles[$role] ?? 0) + 1;
    }
    arsort($roles);
    foreach (array_slice($roles, 0, 4, true) as $role => $count) {
      $nodes[] = vl_constellation_node('role_' . preg_replace('/[^a-z0-9]/', '_', $role), ucwords(str_replace('_', ' ', $role)), $color, min(8, max(3, $count + 3)), $count . ' users');
    }
  }

  if (!$nodes) {
    $nodes[] = vl_constellation_node('users_placeholder', 'Users', $color, 3, 'User roster not available');
  }

  return vl_constellation_category('users', 'User Accounts & Roles', $color, $icon, $nodes);
}

function vl_constellation_ai_category(string $color, string $icon, array $conversations): array {
  $nodes = [];

  $conversation_count = count($conversations);
  if ($conversation_count) {
    $nodes[] = vl_constellation_node('conversations_total', 'Conversations', $color, min(10, max(4, $conversation_count + 3)), $conversation_count . ' logged');

    $messages = 0;
    $last = 0;
    foreach ($conversations as $conversation) {
      if (!is_array($conversation)) continue;
      $messages += is_array($conversation['transcript'] ?? null) ? count($conversation['transcript']) : 0;
      $ended = $conversation['timestamp'] ?? ($conversation['received_at'] ?? 0);
      if ($ended > $last) $last = (int)$ended;
    }
    if ($messages) {
      $nodes[] = vl_constellation_node('messages', 'Messages', $color, min(9, max(3, $messages / 2)), $messages . ' exchanges');
    }
    if ($last) {
      $nodes[] = vl_constellation_node('last_conversation', 'Last Conversation', $color, 6, vl_constellation_time_ago($last));
    }
  }

  if (!$nodes) {
    $nodes[] = vl_constellation_node('conversations_placeholder', 'AI Chats', $color, 3, 'No conversations logged');
  }

  return vl_constellation_category('ai', 'AI Conversations', $color, $icon, $nodes);
}

function vl_constellation_sessions_category(string $color, string $icon, array $session_starts, array $session_ends): array {
  $nodes = [];
  $start_count = count($session_starts);
  $end_count   = count($session_ends);

  if ($start_count) {
    $nodes[] = vl_constellation_node('sessions_started', 'Sessions Started', $color, min(9, max(3, $start_count + 2)), $start_count . ' sessions');
  }
  if ($end_count) {
    $nodes[] = vl_constellation_node('sessions_closed', 'Sessions Closed', $color, min(9, max(3, $end_count + 2)), $end_count . ' sessions');
  }

  $timeouts = 0;
  $last_end = 0;
  foreach ($session_ends as $session) {
    if (!is_array($session)) continue;
    $reason = strtolower((string)($session['reason'] ?? ''));
    if (strpos($reason, 'timeout') !== false || strpos($reason, 'inactive') !== false) {
      $timeouts++;
    }
    $ended = $session['timestamp'] ?? ($session['ended_at'] ?? 0);
    if ($ended > $last_end) $last_end = (int)$ended;
  }

  if ($timeouts) {
    $nodes[] = vl_constellation_node('session_timeouts', 'Inactive Closures', $color, min(8, max(3, $timeouts + 2)), $timeouts . ' auto-closed');
  }
  if ($last_end) {
    $nodes[] = vl_constellation_node('last_session', 'Last Session', $color, 5, vl_constellation_time_ago($last_end));
  }

  if (!$nodes) {
    $nodes[] = vl_constellation_node('sessions_placeholder', 'Sessions', $color, 3, 'No session telemetry yet');
  }

  return vl_constellation_category('sessions', 'Sessions & Engagement', $color, $icon, $nodes);
}

function vl_constellation_integrations_category(string $color, string $icon, array $connections): array {
  $nodes = [];
  if ($connections) {
    $nodes[] = vl_constellation_node('integrations_total', 'Integrations', $color, min(9, max(3, count($connections) + 2)), count($connections) . ' connected');
    $index = 0;
    foreach ($connections as $key => $row) {
      if ($index >= 5) break;
      if (is_array($row)) {
        $provider = $row['provider'] ?? ($row['name'] ?? $key);
        $status = !empty($row['status']) ? vl_constellation_string($row['status']) : (!empty($row['connected']) ? 'Connected' : 'Unknown');
      } else {
        $provider = $key;
        $status = is_scalar($row) ? (string)$row : 'Available';
      }
      $nodes[] = vl_constellation_node('integration_' . $index, vl_constellation_string((string)$provider), $color, 4, $status);
      $index++;
    }
  }

  if (!$nodes) {
    $nodes[] = vl_constellation_node('integrations_placeholder', 'Cloud Integrations', $color, 3, 'No connections synced');
  }

  return vl_constellation_category('integrations', 'Integrations & Signals', $color, $icon, $nodes);
}

function vl_constellation_category(string $slug, string $label, string $color, string $icon, array $nodes): array {
  return [
    'slug'  => $slug,
    'name'  => $label,
    'color' => $color,
    'icon'  => $icon,
    'nodes' => array_values($nodes),
  ];
}

function vl_constellation_node(string $id, string $label, string $color, int $value, string $detail): array {
  return [
    'id'     => $id,
    'label'  => $label,
    'color'  => $color,
    'value'  => max(1, $value),
    'detail' => $detail,
  ];
}

function vl_constellation_flatten_security(array $security): array {
  $nodes = [];
  $index = 0;

  $walker = function ($prefix, $value) use (&$nodes, &$walker, &$index) {
    if (is_array($value)) {
      foreach ($value as $key => $child) {
        $walker(trim($prefix . ' ' . vl_constellation_human_label((string)$key)), $child);
      }
      return;
    }

    $label = trim($prefix);
    if ($label === '') {
      $label = 'Security Signal';
    }

    $detail = '';
    $score  = 4;

    if (is_bool($value)) {
      $detail = $value ? 'Enabled' : 'Disabled';
      $score = $value ? 7 : 3;
    } elseif (is_numeric($value)) {
      $detail = (string)$value;
      $score = (int)max(3, min(10, abs((float)$value) + 3));
    } elseif (is_string($value)) {
      $detail = trim($value) === '' ? 'Unavailable' : vl_constellation_string($value);
      $score = 4;
    } else {
      $detail = 'Reported';
    }

    $nodes[] = [
      'id'    => 'security_' . $index++,
      'label' => $label,
      'value' => $score,
      'detail'=> $detail,
    ];
  };

  $walker('', $security);

  return $nodes;
}

function vl_constellation_time_ago($timestamp): string {
  $timestamp = is_numeric($timestamp) ? (int)$timestamp : strtotime((string)$timestamp);
  if (!$timestamp) {
    return 'No activity recorded';
  }
  $diff = time() - $timestamp;
  if ($diff < 0) $diff = 0;

  $units = [
    ['year', 365*24*3600],
    ['month', 30*24*3600],
    ['day', 24*3600],
    ['hour', 3600],
    ['minute', 60],
    ['second', 1],
  ];

  foreach ($units as [$name, $secs]) {
    if ($diff >= $secs) {
      $value = (int)floor($diff / $secs);
      return $value . ' ' . $name . ($value === 1 ? '' : 's') . ' ago';
    }
  }

  return 'Just now';
}

function vl_constellation_date($timestamp): string {
  if (empty($timestamp)) {
    return '';
  }
  if (is_numeric($timestamp)) {
    return date('c', (int)$timestamp);
  }
  $parsed = strtotime((string)$timestamp);
  return $parsed ? date('c', $parsed) : '';
}

function vl_constellation_string($value): string {
  return trim(wp_strip_all_tags((string)$value));
}

function vl_constellation_redact_key(string $key): string {
  $key = trim($key);
  if ($key === '') {
    return '';
  }
  if (strlen($key) <= 6) {
    return str_repeat('•', strlen($key));
  }
  return substr($key, 0, 4) . '…' . substr($key, -4);
}

function vl_constellation_human_label(string $key): string {
  $key = trim($key);
  if ($key === '') return 'Item';
  $key = str_replace(['_', '-'], ' ', $key);
  return ucwords(preg_replace('/\s+/', ' ', $key));
}

/**
 * Field validation endpoint
 */
add_action('rest_api_init', function () {
  register_rest_route('luna_widget/v1', '/validate/field', [
    'methods' => 'POST',
    'permission_callback' => '__return_true',
    'callback' => function (WP_REST_Request $req) {
      $license = $req->get_header('X-Luna-License') ?: $req->get_param('license');
      if (!$license) {
        return new WP_REST_Response(['error' => 'License required'], 401);
      }
      
      $field = $req->get_param('field');
      if (!$field) {
        return new WP_REST_Response(['error' => 'Field name required'], 400);
      }
      
      // Find the license ID from the license key
      $licenses = get_option('vl_licenses_registry', []);
      $license_id = null;
      foreach ($licenses as $id => $lic) {
        if ($lic['key'] === $license) {
          $license_id = $id;
          break;
        }
      }
      
      if (!$license_id) {
        return new WP_REST_Response(['error' => 'License not found'], 404);
      }
      
      // Get client profile data
      $profiles = get_option('vl_hub_profiles', []);
      $profile = $profiles[$license_id] ?? [];
      
      // Validate the specific field
      $validation_result = vl_validate_field_mapping($profile, $field);
      
      return new WP_REST_Response([
        'field' => $field,
        'valid' => $validation_result['valid'],
        'value' => $validation_result['value'],
        'error' => $validation_result['error'] ?? null,
        'timestamp' => current_time('mysql')
      ], 200);
    }
  ]);
});

/**
 * Validate all fields endpoint
 */
add_action('rest_api_init', function () {
  register_rest_route('luna_widget/v1', '/validate/all', [
    'methods' => 'POST',
    'permission_callback' => '__return_true',
    'callback' => function (WP_REST_Request $req) {
      $license = $req->get_header('X-Luna-License') ?: $req->get_param('license');
      if (!$license) {
        return new WP_REST_Response(['error' => 'License required'], 401);
      }
      
      // Find the license ID from the license key
      $licenses = get_option('vl_licenses_registry', []);
      $license_id = null;
      foreach ($licenses as $id => $lic) {
        if ($lic['key'] === $license) {
          $license_id = $id;
          break;
        }
      }
      
      if (!$license_id) {
        return new WP_REST_Response(['error' => 'License not found'], 404);
      }
      
      // Get client profile data
      $profiles = get_option('vl_hub_profiles', []);
      $profile = $profiles[$license_id] ?? [];
      
      // Validate all fields
      $all_fields = [
        'tls_status', 'tls_version', 'tls_issuer', 'tls_provider_guess',
        'tls_valid_from', 'tls_valid_to', 'tls_host',
        'waf_provider', 'waf_last_audit',
        'ids_provider', 'ids_last_scan', 'ids_result', 'ids_schedule',
        'auth_mfa', 'auth_password_policy', 'auth_session_timeout', 'auth_sso_providers',
        'domain_registrar', 'domain_registered_on', 'domain_renewal_date', 'domain_auto_renew', 'domain_dns_records'
      ];
      
      $results = [];
      foreach ($all_fields as $field) {
        $results[$field] = vl_validate_field_mapping($profile, $field);
      }
      
      return new WP_REST_Response([
        'license_id' => $license_id,
        'validations' => $results,
        'timestamp' => current_time('mysql')
      ], 200);
    }
  ]);
});

/**
 * Field validation helper function
 */
function vl_validate_field_mapping($profile, $field) {
  $security = $profile['security'] ?? [];
  
  switch ($field) {
    case 'tls_status':
      $value = $security['tls']['status'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'TLS status not found' : null
      ];
      
    case 'tls_version':
      $value = $security['tls']['version'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'TLS version not found' : null
      ];
      
    case 'tls_issuer':
      $value = $security['tls']['issuer'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'TLS issuer not found' : null
      ];
      
    case 'tls_provider_guess':
      $value = $security['tls']['provider_guess'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'TLS provider guess not found' : null
      ];
      
    case 'tls_valid_from':
      $value = $security['tls']['valid_from'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'TLS valid from date not found' : null
      ];
      
    case 'tls_valid_to':
      $value = $security['tls']['valid_to'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'TLS valid to date not found' : null
      ];
      
    case 'tls_host':
      $value = $security['tls']['host'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'TLS host not found' : null
      ];
      
    case 'waf_provider':
      $value = $security['waf']['provider'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'WAF provider not found' : null
      ];
      
    case 'waf_last_audit':
      $value = $security['waf']['last_audit'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'WAF last audit not found' : null
      ];
      
    case 'ids_provider':
      $value = $security['ids']['provider'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'IDS provider not found' : null
      ];
      
    case 'ids_last_scan':
      $value = $security['ids']['last_scan'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'IDS last scan not found' : null
      ];
      
    case 'ids_result':
      $value = $security['ids']['result'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'IDS result not found' : null
      ];
      
    case 'ids_schedule':
      $value = $security['ids']['schedule'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'IDS schedule not found' : null
      ];
      
    case 'auth_mfa':
      $value = $security['auth']['mfa'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'MFA not found' : null
      ];
      
    case 'auth_password_policy':
      $value = $security['auth']['password_policy'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'Password policy not found' : null
      ];
      
    case 'auth_session_timeout':
      $value = $security['auth']['session_timeout'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'Session timeout not found' : null
      ];
      
    case 'auth_sso_providers':
      $value = $security['auth']['sso_providers'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'SSO providers not found' : null
      ];
      
    case 'domain_registrar':
      $value = $security['domain']['registrar'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'Domain registrar not found' : null
      ];
      
    case 'domain_registered_on':
      $value = $security['domain']['registered_on'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'Domain registration date not found' : null
      ];
      
    case 'domain_renewal_date':
      $value = $security['domain']['renewal_date'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'Domain renewal date not found' : null
      ];
      
    case 'domain_auto_renew':
      $value = $security['domain']['auto_renew'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'Domain auto-renewal setting not found' : null
      ];
      
    case 'domain_dns_records':
      $value = $security['domain']['dns_records'] ?? '';
      return [
        'valid' => !empty($value),
        'value' => $value,
        'error' => empty($value) ? 'DNS records not found' : null
      ];
      
    default:
  return [
        'valid' => false,
        'value' => '',
        'error' => 'Unknown field: ' . $field
      ];
  }
}

/**
 * Test endpoint
 */
add_action('rest_api_init', function () {
  register_rest_route('luna_widget/v1', '/test', [
    'methods' => 'GET',
    'permission_callback' => '__return_true',
    'callback' => function (WP_REST_Request $req) {
      return new WP_REST_Response([
        'status' => 'ok',
        'message' => 'Luna Hub test endpoint working',
        'license' => $req->get_param('license') ?: 'none',
      ], 200);
    }
  ]);
});

/* =========================================================================
 * VL Client Authentication Endpoints
 * ========================================================================= */

/**
 * Client authentication check endpoint
 */
add_action('rest_api_init', function () {
  register_rest_route('vl-hub/v1', '/auth-check', [
    'methods' => 'GET',
    'callback' => 'vl_check_client_auth',
    'permission_callback' => 'vl_check_client_auth_permissions'
  ]);
});

/**
 * Client data endpoint
 */
add_action('rest_api_init', function () {
  register_rest_route('vl-hub/v1', '/client-data', [
    'methods' => 'GET',
    'callback' => 'vl_get_client_data',
    'permission_callback' => 'vl_check_client_auth_permissions'
  ]);
});

/**
 * Client list endpoint
 */
add_action('rest_api_init', function () {
  register_rest_route('vl-hub/v1', '/clients', [
    'methods' => 'GET',
    'callback' => 'vl_get_clients_for_supercluster',
    'permission_callback' => 'vl_check_client_permissions_supercluster'
  ]);
});

// Authentication check function for clients
function vl_check_client_auth($request) {
    if (!is_user_logged_in()) {
        return new WP_Error('not_authenticated', 'User not logged in', array('status' => 401));
    }
    
    $user = wp_get_current_user();
    $license_key = get_user_meta($user->ID, 'vl_license_key', true);
    $client_name = get_user_meta($user->ID, 'vl_client_name', true);
    
    return array(
        'success' => true,
        'user_id' => $user->ID,
        'username' => $user->user_login,
        'license_key' => $license_key,
        'client_name' => $client_name,
        'is_vl_client' => !empty($license_key)
    );
}

// Client data function
function vl_get_client_data($request) {
    if (!is_user_logged_in()) {
        return new WP_Error('not_authenticated', 'User not logged in', array('status' => 401));
    }
    
    $user = wp_get_current_user();
    $license_key = get_user_meta($user->ID, 'vl_license_key', true);
    $client_name = get_user_meta($user->ID, 'vl_client_name', true);
    
    if (empty($license_key)) {
        return new WP_Error('no_license', 'User is not a VL client', array('status' => 403));
    }
    
    // Map license keys to client configurations
    $client_configs = array(
        'lic_3d2c5795-b6c2-482f-8cb9-cf36603768e8' => array(
            'name' => 'Commonwealth Health Services',
            'color' => '#2B6AFF',
            'focus' => array('infrastructure', 'security', 'analytics', 'identity')
        ),
        'lic_68712354-ee80-4eb9-94d7-1a1f6404bb80' => array(
            'name' => 'Site Assembly',
            'color' => '#D62A42',
            'focus' => array('content', 'search', 'marketing', 'ecommerce')
        ),
        'lic_ce0a7680-26eb-484b-ac1a-bb075d944322' => array(
            'name' => 'Visible Light',
            'color' => '#F4C542',
            'focus' => array('cloudops', 'competitive', 'analytics', 'infrastructure')
        )
    );
    
    $client_config = isset($client_configs[$license_key]) ? $client_configs[$license_key] : null;
    
    return array(
        'success' => true,
        'user_id' => $user->ID,
        'username' => $user->user_login,
        'license_key' => $license_key,
        'client_name' => $client_name,
        'client_config' => $client_config
    );
}

// Get clients from database for Supercluster visualization
function vl_get_clients_for_supercluster($request) {
    $licenses = get_option('vl_licenses_registry', array());
    $clients = array();
    
    // Map license keys to client names
    $client_mapping = array(
        'lic_3d2c5795-b6c2-482f-8cb9-cf36603768e8' => 'Commonwealth Health Services',
        'lic_68712354-ee80-4eb9-94d7-1a1f6404bb80' => 'Site Assembly',
        'lic_ce0a7680-26eb-484b-ac1a-bb075d944322' => 'Visible Light'
    );
    
    if (!empty($licenses) && is_array($licenses)) {
        foreach ($licenses as $license_key => $license_data) {
            // Check if this is one of our mapped licenses
            if (isset($client_mapping[$license_key])) {
                $clients[] = array(
                    'client_name' => $client_mapping[$license_key],
                    'license_key' => $license_key,
                    'status' => 'active'
                );
            }
            // Also check for the old format with client_name field
            elseif (isset($license_data['client_name']) && isset($license_data['status']) && $license_data['status'] === 'active') {
                $clients[] = array(
                    'client_name' => $license_data['client_name'],
                    'license_key' => $license_key,
                    'status' => $license_data['status']
                );
            }
        }
    }
    
    // Fallback if no clients found in registry
    if (empty($clients)) {
        $clients = array(
            array('client_name' => 'Commonwealth Health Services', 'license_key' => 'lic_3d2c5795-b6c2-482f-8cb9-cf36603768e8', 'status' => 'active'),
            array('client_name' => 'Site Assembly', 'license_key' => 'lic_68712354-ee80-4eb9-94d7-1a1f6404bb80', 'status' => 'active'),
            array('client_name' => 'Visible Light', 'license_key' => 'lic_ce0a7680-26eb-484b-ac1a-bb075d944322', 'status' => 'active')
        );
    }
    
    return array('success' => true, 'clients' => $clients, 'count' => count($clients), 'source' => !empty($licenses) ? 'database' : 'fallback');
}

// Permission callbacks
function vl_check_client_auth_permissions($request) {
    return is_user_logged_in();
}

function vl_check_client_permissions_supercluster($request) {
    return true; // Allow public access for now
}

/* =========================================================================
 * Luna Compose long-form endpoint
 * ========================================================================= */
if (!function_exists('vl_luna_compose_resolve_profile')) {
  function vl_luna_compose_resolve_profile(string $client_slug, bool $force_refresh = false) {
    if (!function_exists('vl_hub_profile_resolve')) {
      return new WP_Error('missing_dependency', __('VL Hub profile utilities are unavailable.', 'visible-light'), ['status' => 500]);
    }

    $normalized  = sanitize_title($client_slug ?: 'commonwealthhealthservices');
    $licenses    = get_option('vl_licenses_registry', []);
    $license_key = '';

    if (is_array($licenses)) {
      foreach ($licenses as $id => $row) {
        $candidate_key = '';
        if (is_array($row)) {
          if (!empty($row['key']) && is_string($row['key'])) {
            $candidate_key = $row['key'];
          } elseif (is_string($id)) {
            $candidate_key = $id;
          }
        } elseif (is_string($id)) {
          $candidate_key = $id;
        }

        if ($candidate_key === '') {
          continue;
        }

        $name_slug = '';
        if (is_array($row) && !empty($row['client_name'])) {
          $name_slug = sanitize_title($row['client_name']);
        }

        $site_slug = '';
        if (is_array($row) && !empty($row['site'])) {
          $site_slug = sanitize_title(str_replace(['https://', 'http://', 'www.'], '', $row['site']));
        }

        if ($name_slug === $normalized || $site_slug === $normalized) {
          $license_key = $candidate_key;
          break;
        }
      }
    }

    if ($license_key === '') {
      $fallback_map = [
        'commonwealthhealthservices' => [
          'VL-VYAK-9BPQ-NKCC',
          'VL-GC5K-YKBM-BM5F',
          'lic_3d2c5795-b6c2-482f-8cb9-cf36603768e8',
        ],
      ];

      $candidates = $fallback_map[$normalized] ?? [];
      foreach ($candidates as $candidate) {
        if (!function_exists('vl_hub_find_license_record')) {
          $license_key = $candidate;
          break;
        }

        $record = vl_hub_find_license_record($candidate);
        if (!empty($record)) {
          $license_key = $candidate;
          break;
        }

        if (is_array($licenses)) {
          $licenses[$candidate] = [
            'key'         => $candidate,
            'client_name' => 'Commonwealth Health Services',
            'site'        => 'https://commonwealthhealthservices.com',
            'status'      => 'active',
            'created'     => current_time('mysql'),
          ];
          update_option('vl_licenses_registry', $licenses);
        }

        $license_key = $candidate;
        break;
      }
    }

    if ($license_key === '') {
      return new WP_Error('client_not_found', __('Unable to locate a VL Hub license for the requested client.', 'visible-light'), ['status' => 404]);
    }

    $profile = vl_hub_profile_resolve($license_key, ['force_refresh' => $force_refresh]);
    if (is_wp_error($profile)) {
      return $profile;
    }

    if (!is_array($profile)) {
      return new WP_Error('profile_unavailable', __('The VL Hub profile did not return usable data.', 'visible-light'), ['status' => 500]);
    }

    if (empty($profile['client_name'])) {
      $profile['client_name'] = ucwords(str_replace('-', ' ', $normalized));
    }

    if (empty($profile['home_url'])) {
      if (!empty($profile['site']['home_url'])) {
        $profile['home_url'] = $profile['site']['home_url'];
      } elseif (!empty($profile['site']) && is_string($profile['site'])) {
        $profile['home_url'] = $profile['site'];
      } else {
        $profile['home_url'] = 'https://commonwealthhealthservices.com';
      }
    }

    $profile['client_slug'] = $normalized;
    $profile['license_key'] = $license_key;

    return $profile;
  }
}

if (!function_exists('vl_luna_compose_render_answer')) {
  function vl_luna_compose_render_answer(string $prompt, array $profile): string {
    $prompt_trimmed = trim($prompt);
    $client_name    = isset($profile['client_name']) && $profile['client_name'] !== '' ? $profile['client_name'] : 'Commonwealth Health Services';
    $site_url       = isset($profile['home_url']) && $profile['home_url'] !== '' ? $profile['home_url'] : 'https://commonwealthhealthservices.com';
    $host           = wp_parse_url($site_url, PHP_URL_HOST);
    if (!is_string($host) || $host === '') {
      $host = $site_url;
    }

    $counts = isset($profile['counts']) && is_array($profile['counts']) ? $profile['counts'] : [];
    $count_posts   = isset($counts['posts']) ? (int) $counts['posts'] : 0;
    $count_pages   = isset($counts['pages']) ? (int) $counts['pages'] : 0;
    $count_users   = isset($counts['users']) ? (int) $counts['users'] : 0;
    $count_plugins = isset($counts['plugins']) ? (int) $counts['plugins'] : 0;

    $wordpress  = isset($profile['wordpress']) && is_array($profile['wordpress']) ? $profile['wordpress'] : [];
    $wp_version = '';
    if (!empty($wordpress['version'])) {
      $wp_version = (string) $wordpress['version'];
    } elseif (!empty($wordpress['core']['version'])) {
      $wp_version = (string) $wordpress['core']['version'];
    }

    $themes = isset($profile['themes']) && is_array($profile['themes']) ? $profile['themes'] : [];
    $active_theme = '';
    foreach ($themes as $theme) {
      if (!is_array($theme)) {
        continue;
      }
      $is_active = !empty($theme['is_active']) || !empty($theme['active']);
      if ($is_active) {
        $label = !empty($theme['name']) ? $theme['name'] : (!empty($theme['title']) ? $theme['title'] : 'Active theme');
        if (!empty($theme['version'])) {
          $label .= ' v' . $theme['version'];
        }
        $active_theme = $label;
        break;
      }
    }
    if ($active_theme === '' && !empty($wordpress['theme']['name'])) {
      $active_theme = (string) $wordpress['theme']['name'];
      if (!empty($wordpress['theme']['version'])) {
        $active_theme .= ' v' . $wordpress['theme']['version'];
      }
    }

    $plugins = isset($profile['plugins']) && is_array($profile['plugins']) ? $profile['plugins'] : [];
    $active_plugins = [];
    $plugin_updates = 0;
    foreach ($plugins as $plugin) {
      if (!is_array($plugin)) {
        continue;
      }
      $name = '';
      if (!empty($plugin['name'])) {
        $name = (string) $plugin['name'];
      } elseif (!empty($plugin['title'])) {
        $name = (string) $plugin['title'];
      } elseif (!empty($plugin['slug'])) {
        $name = (string) $plugin['slug'];
      }
      if ($name === '') {
        continue;
      }

      $is_active = !empty($plugin['is_active']) || !empty($plugin['active']);
      if ($is_active) {
        if (!empty($plugin['version'])) {
          $active_plugins[] = $name . ' v' . $plugin['version'];
        } else {
          $active_plugins[] = $name;
        }
      }

      if (!empty($plugin['update_available']) || !empty($plugin['updates_available']) || !empty($plugin['update'])) {
        $plugin_updates++;
      }
    }
    $active_plugins = array_slice($active_plugins, 0, 6);

    $themes_with_updates = 0;
    foreach ($themes as $theme) {
      if (!is_array($theme)) {
        continue;
      }
      if (!empty($theme['update_available']) || !empty($theme['updates_available']) || !empty($theme['update'])) {
        $themes_with_updates++;
      }
    }

    $updates      = isset($profile['updates']) && is_array($profile['updates']) ? $profile['updates'] : [];
    $core_updates = isset($updates['core']) ? (int) $updates['core'] : 0;

    $security  = isset($profile['security']) && is_array($profile['security']) ? $profile['security'] : [];
    $tls_data  = [];
    if (!empty($security['tls']) && is_array($security['tls'])) {
      $tls_data = $security['tls'];
    } elseif (!empty($profile['tls']) && is_array($profile['tls'])) {
      $tls_data = $profile['tls'];
    }
    $tls_valid   = isset($tls_data['valid']) ? (bool) $tls_data['valid'] : null;
    $tls_expires = '';
    foreach (['valid_to', 'expires', 'expires_at', 'not_after'] as $key) {
      if (!empty($tls_data[$key])) {
        $tls_expires = (string) $tls_data[$key];
        break;
      }
    }
    $tls_provider = !empty($tls_data['issuer']) ? (string) $tls_data['issuer'] : (!empty($tls_data['provider_guess']) ? (string) $tls_data['provider_guess'] : '');

    $waf_info      = isset($security['waf']) && is_array($security['waf']) ? $security['waf'] : [];
    $waf_provider  = !empty($waf_info['provider']) ? (string) $waf_info['provider'] : '';
    $waf_last_audit= !empty($waf_info['last_audit']) ? (string) $waf_info['last_audit'] : '';

    $ids_info     = isset($security['ids']) && is_array($security['ids']) ? $security['ids'] : [];
    $ids_provider = !empty($ids_info['provider']) ? (string) $ids_info['provider'] : '';
    $ids_last_scan= !empty($ids_info['last_scan']) ? (string) $ids_info['last_scan'] : '';
    $ids_schedule = !empty($ids_info['schedule']) ? (string) $ids_info['schedule'] : '';

    $auth_info        = isset($security['auth']) && is_array($security['auth']) ? $security['auth'] : [];
    $mfa              = !empty($auth_info['mfa']) ? (string) $auth_info['mfa'] : '';
    $password_policy  = !empty($auth_info['password_policy']) ? (string) $auth_info['password_policy'] : '';
    $session_timeout  = !empty($auth_info['session_timeout']) ? (string) $auth_info['session_timeout'] : '';
    $sso_providers    = !empty($auth_info['sso_providers']) ? (string) $auth_info['sso_providers'] : '';

    $ga4_metrics = [];
    if (!empty($profile['ga4_metrics']) && is_array($profile['ga4_metrics'])) {
      $ga4_metrics = $profile['ga4_metrics'];
    } elseif (!empty($profile['analytics']['ga4']['metrics']) && is_array($profile['analytics']['ga4']['metrics'])) {
      $ga4_metrics = $profile['analytics']['ga4']['metrics'];
    }
    $ga4_range = '';
    if (!empty($profile['ga4_date_range'])) {
      $ga4_range = (string) $profile['ga4_date_range'];
    } elseif (!empty($profile['analytics']['ga4']['date_range'])) {
      $ga4_range = (string) $profile['analytics']['ga4']['date_range'];
    }

    $posts     = isset($profile['posts']) && is_array($profile['posts']) ? $profile['posts'] : [];
    $top_posts = [];
    foreach ($posts as $post) {
      if (!is_array($post) || empty($post['title'])) {
        continue;
      }
      $top_posts[] = (string) $post['title'];
      if (count($top_posts) >= 3) {
        break;
      }
    }

    $last_synced = '';
    foreach (['profile_last_synced', 'last_updated', 'generated'] as $key) {
      if (!empty($profile[$key])) {
        $last_synced = (string) $profile[$key];
        break;
      }
    }
    if ($last_synced !== '') {
      $timestamp = strtotime($last_synced);
      if ($timestamp) {
        $timezone = get_option('timezone_string');
        if ($timezone) {
          $dt = new DateTime('@' . $timestamp);
          try {
            $dt->setTimezone(new DateTimeZone($timezone));
            $last_synced = $dt->format('F j, Y \a\t g:i A T');
          } catch (Exception $e) {
            $last_synced = gmdate('F j, Y \a\t g:i A \U\T\C', $timestamp);
          }
        } else {
          $last_synced = gmdate('F j, Y \a\t g:i A \U\T\C', $timestamp);
        }
      }
    }

    $https_status = isset($profile['https']) ? (bool) $profile['https'] : (stripos($site_url, 'https://') === 0);

    $summary_points   = [];
    $summary_points[] = sprintf('%s is running WordPress %s on %s with HTTPS %s.',
      $client_name,
      $wp_version !== '' ? $wp_version : __('(version unknown)', 'visible-light'),
      $host,
      $https_status ? __('enforced', 'visible-light') : __('not fully enforced', 'visible-light')
    );
    $summary_points[] = sprintf('Visible Light Hub currently tracks %d pages, %d posts, %d users, and %d plugins for this property.', $count_pages, $count_posts, $count_users, $count_plugins);

    if ($plugin_updates > 0 || $themes_with_updates > 0 || $core_updates > 0) {
      $summary_points[] = sprintf('Update queue: %d plugin(s), %d theme(s), and %s WordPress core updates awaiting review.', $plugin_updates, $themes_with_updates, $core_updates > 0 ? (string) $core_updates : __('no', 'visible-light'));
    } else {
      $summary_points[] = __('All tracked plugins, themes, and WordPress core are reported as current.', 'visible-light');
    }

    if ($tls_valid === true) {
      $summary_points[] = $tls_expires !== ''
        ? sprintf('TLS certificate is confirmed active through %s (%s).', $tls_expires, $tls_provider ?: __('issuer unknown', 'visible-light'))
        : __('TLS certificate is confirmed active.', 'visible-light');
    } elseif ($tls_valid === false) {
      $summary_points[] = __('TLS status needs attention—no valid certificate details are recorded in Hub.', 'visible-light');
    }

    $key_findings   = [];
    $key_findings[] = 'Infrastructure & Platform:';
    $key_findings[] = sprintf('  • WordPress %s with %s as the active theme.', $wp_version !== '' ? $wp_version : __('version unknown', 'visible-light'), $active_theme !== '' ? $active_theme : __('theme not identified', 'visible-light'));
    $key_findings[] = sprintf('  • %d active plugin integrations (top entries: %s).', count($active_plugins), $active_plugins ? implode(', ', $active_plugins) : __('not captured', 'visible-light'));
    $key_findings[] = sprintf('  • Hosting endpoint resolved as %s with HTTPS %s.', $host, $https_status ? __('enabled', 'visible-light') : __('disabled or unverified', 'visible-light'));

    $key_findings[] = 'Security & Compliance:';
    if ($tls_valid === true) {
      $key_findings[] = sprintf('  • TLS certificate active%s.', $tls_expires !== '' ? ' (expires ' . $tls_expires . ')' : '');
    } else {
      $key_findings[] = '  • TLS certificate validity requires confirmation.';
    }
    $key_findings[] = $waf_provider !== ''
      ? sprintf('  • Web application firewall provided by %s%s.', $waf_provider, $waf_last_audit !== '' ? ' (last audit ' . $waf_last_audit . ')' : '')
      : '  • No WAF provider is documented in the Hub profile.';
    $key_findings[] = $ids_provider !== ''
      ? sprintf('  • Threat protection by %s%s%s.', $ids_provider, $ids_last_scan !== '' ? ', last scan ' . $ids_last_scan : '', $ids_schedule !== '' ? ', schedule ' . $ids_schedule : '')
      : '  • No intrusion detection telemetry is synced.';
    if ($mfa !== '' || $password_policy !== '' || $session_timeout !== '' || $sso_providers !== '') {
      $auth_details = array_filter([
        $mfa !== '' ? 'MFA: ' . $mfa : '',
        $password_policy !== '' ? 'Password policy: ' . $password_policy : '',
        $session_timeout !== '' ? 'Session timeout: ' . $session_timeout : '',
        $sso_providers !== '' ? 'SSO: ' . $sso_providers : '',
      ]);
      if ($auth_details) {
        $key_findings[] = '  • Authentication controls — ' . implode('; ', $auth_details) . '.';
      }
    }

    $key_findings[] = 'Content & Audience:';
    $key_findings[] = sprintf('  • Hub indexes %d published pages and %d posts; top content includes %s.', $count_pages, $count_posts, $top_posts ? implode(', ', $top_posts) : __('(no titles provided)', 'visible-light'));
    $key_findings[] = sprintf('  • %d total WordPress user accounts are registered.', $count_users);

    $key_findings[] = 'Analytics & Signals:';
    if ($ga4_metrics) {
      $metric_lines = [];
      foreach ($ga4_metrics as $metric_key => $metric_value) {
        if ($metric_value === '' || $metric_value === null) {
          continue;
        }
        $label = ucwords(str_replace(['_', '-'], ' ', (string) $metric_key));
        $metric_lines[] = $label . ': ' . (is_scalar($metric_value) ? $metric_value : wp_json_encode($metric_value));
        if (count($metric_lines) >= 4) {
          break;
        }
      }
      if ($metric_lines) {
        $key_findings[] = '  • GA4 metrics (' . ($ga4_range !== '' ? $ga4_range : __('latest sync', 'visible-light')) . '): ' . implode('; ', $metric_lines) . '.';
      }
    } else {
      $key_findings[] = '  • No GA4 analytics metrics have been synced for this property.';
    }

    $recommendations = [];
    if ($plugin_updates > 0) {
      $recommendations[] = sprintf('Schedule a maintenance window to apply %d pending plugin update(s); prioritize security-sensitive components first.', $plugin_updates);
    }
    if ($themes_with_updates > 0) {
      $recommendations[] = sprintf('Review the %d theme update(s) awaiting deployment to maintain visual and security parity.', $themes_with_updates);
    }
    if ($core_updates > 0) {
      $recommendations[] = 'Coordinate a WordPress core upgrade to the latest supported release to preserve platform supportability.';
    }
    if ($tls_valid !== true) {
      $recommendations[] = 'Engage the infrastructure team to confirm certificate issuance and renewals for the production domain.';
    }
    if ($waf_provider === '') {
      $recommendations[] = 'Evaluate adding a managed WAF service (e.g., Cloudflare or Fastly) to extend perimeter protection.';
    }
    if ($ids_provider === '') {
      $recommendations[] = 'Introduce malware scanning or IDS coverage to close detection gaps across the application tier.';
    }
    if (empty($recommendations)) {
      $recommendations[] = 'No immediate remediation is required based on the latest Hub telemetry. Maintain standard monitoring cadence.';
    }

    $snapshot   = [];
    $snapshot[] = sprintf('Site URL: %s', $site_url);
    if ($last_synced !== '') {
      $snapshot[] = 'Profile last synced: ' . $last_synced;
    }
    $snapshot[] = sprintf('WordPress version: %s', $wp_version !== '' ? $wp_version : __('unknown', 'visible-light'));
    if ($active_theme !== '') {
      $snapshot[] = 'Active theme: ' . $active_theme;
    }
    $snapshot[] = sprintf('Active plugins: %d', count($active_plugins));
    $snapshot[] = sprintf('Pending updates — plugins: %d, themes: %d, core: %d', $plugin_updates, $themes_with_updates, $core_updates);
    if ($tls_valid !== null) {
      $snapshot[] = 'TLS valid: ' . ($tls_valid ? 'yes' : 'no');
    }
    if ($tls_expires !== '') {
      $snapshot[] = 'TLS expires: ' . $tls_expires;
    }
    if ($waf_provider !== '') {
      $snapshot[] = 'WAF provider: ' . $waf_provider;
    }
    if ($ids_provider !== '') {
      $snapshot[] = 'IDS provider: ' . $ids_provider;
    }
    if ($ga4_range !== '') {
      $snapshot[] = 'GA4 range: ' . $ga4_range;
    }

    $lines   = [];
    $lines[] = 'Subject: ' . $client_name . ' – ' . ($prompt_trimmed !== '' ? $prompt_trimmed : __('Luna Compose Update', 'visible-light'));
    $lines[] = '';
    $lines[] = 'Team ' . $client_name . ',';
    $lines[] = '';
    $lines[] = sprintf('Thank you for your request regarding "%s." The summary below reflects the most recent telemetry synchronized from Visible Light Hub for %s.', $prompt_trimmed !== '' ? $prompt_trimmed : __('current operations', 'visible-light'), $site_url);
    $lines[] = '';
    $lines[] = 'Executive Summary';
    $lines[] = '-----------------';
    foreach ($summary_points as $point) {
      $lines[] = '- ' . $point;
    }
    $lines[] = '';
    $lines[] = 'Key Findings';
    $lines[] = '------------';
    foreach ($key_findings as $finding) {
      $lines[] = $finding;
    }
    $lines[] = '';
    $lines[] = 'Recommended Next Steps';
    $lines[] = '-----------------------';
    foreach ($recommendations as $recommendation) {
      $lines[] = '- ' . $recommendation;
    }
    $lines[] = '';
    $lines[] = 'Data Snapshot';
    $lines[] = '-------------';
    foreach ($snapshot as $item) {
      $lines[] = '- ' . $item;
    }
    $lines[] = '';
    if ($prompt_trimmed !== '') {
      $lines[] = 'Prompt reference: ' . $prompt_trimmed;
      $lines[] = '';
    }
    $lines[] = 'Please let me know if you would like this prepared as outbound client communication or if deeper analysis is required on any of the items above.';
    $lines[] = '';
    $lines[] = 'Regards,';
    $lines[] = 'Luna Compose';

    return implode("\n", $lines);
  }
}

if (!function_exists('vl_luna_compose_rest_respond')) {
  function vl_luna_compose_rest_respond(WP_REST_Request $request) {
    $prompt = trim((string) $request->get_param('prompt'));
    if ($prompt === '') {
      return new WP_REST_Response(['error' => 'Prompt is required.'], 400);
    }

    $client_slug = $request->get_param('client');
    if (!is_string($client_slug) || $client_slug === '') {
      $client_slug = 'commonwealthhealthservices';
    }

    $force_refresh = filter_var($request->get_param('refresh'), FILTER_VALIDATE_BOOLEAN);

    $profile = vl_luna_compose_resolve_profile($client_slug, $force_refresh);
    if (is_wp_error($profile)) {
      $status = (int) ($profile->get_error_data('status') ?? 500);
      return new WP_REST_Response([
        'error' => $profile->get_error_message(),
        'code'  => $profile->get_error_code(),
      ], $status);
    }

    $answer = vl_luna_compose_render_answer($prompt, $profile);

    $meta = [
      'client'  => isset($profile['client_name']) ? (string) $profile['client_name'] : '',
      'site'    => isset($profile['home_url']) ? (string) $profile['home_url'] : '',
      'license' => isset($profile['license_key']) ? (string) $profile['license_key'] : '',
      'source'  => 'vl-hub compose',
    ];
    if (!empty($profile['profile_last_synced'])) {
      $meta['profile_last_synced'] = $profile['profile_last_synced'];
    } elseif (!empty($profile['last_updated'])) {
      $meta['profile_last_synced'] = $profile['last_updated'];
    }

    return rest_ensure_response([
      'answer' => $answer,
      'meta'   => $meta,
    ]);
  }
}

add_action('rest_api_init', function () {
  register_rest_route('luna_compose/v1', '/respond', [
    'methods'             => \WP_REST_Server::CREATABLE,
    'permission_callback' => '__return_true',
    'callback'            => 'vl_luna_compose_rest_respond',
    'args'                => [
      'prompt'  => [
        'type'     => 'string',
        'required' => true,
      ],
      'client'  => [
        'type'     => 'string',
        'required' => false,
      ],
      'refresh' => [
        'type'     => 'boolean',
        'required' => false,
      ],
    ],
  ]);
});

/* =========================================================================
 * VL Domain Ranking (VLDR) Integration for Luna Chat
 * ========================================================================= */

/**
 * Get VLDR score from Hub with caching to avoid chat-storming.
 * 
 * @param string $license_key The license key
 * @param string $domain The domain to check
 * @return array|null VLDR data or null on failure
 */
function luna_vldr_get_score_from_hub(string $license_key, string $domain): ?array {
  if (empty($license_key) || empty($domain)) {
    return null;
  }

  // Clean domain (remove protocol, www, trailing slashes)
  $domain = preg_replace('/^https?:\/\//', '', $domain);
  $domain = preg_replace('/^www\./', '', $domain);
  $domain = rtrim($domain, '/');
  $domain = strtolower($domain);

  // Cache key with 30-minute TTL
  $cache_key = 'luna_vldr_' . md5($license_key . '|' . $domain);
  $cached = get_transient($cache_key);
  if ($cached !== false && is_array($cached)) {
    return $cached;
  }

  // Fetch from Hub REST API
  $hub_url = apply_filters('luna_hub_base_url', 'https://visiblelight.ai');
  $url = trailingslashit($hub_url) . 'wp-json/vl-hub/v1/vldr?license=' . rawurlencode($license_key) . '&domain=' . rawurlencode($domain);

  $res = wp_remote_get($url, [
    'timeout' => 15,
    'sslverify' => true,
    'headers' => [
      'Accept' => 'application/json',
    ],
  ]);

  if (is_wp_error($res)) {
    error_log('[Luna VLDR] Error fetching from Hub: ' . $res->get_error_message());
    return null;
  }

  $code = wp_remote_retrieve_response_code($res);
  if ($code !== 200) {
    error_log('[Luna VLDR] HTTP ' . $code . ' from Hub for domain: ' . $domain);
    return null;
  }

  $body = wp_remote_retrieve_body($res);
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

/**
 * Enrich chat context with VLDR data for competitors.
 * 
 * This filter allows Luna to answer "What's their Domain Ranking?" questions
 * by providing VLDR data in the chat context.
 * 
 * @param array $context The chat context array
 * @return array Enriched context with VLDR data
 */
add_filter('luna_chat_context_enrich', function (array $context): array {
  $license_key = $context['license_key'] ?? '';
  if (empty($license_key)) {
    return $context;
  }

  // Extract competitor domains from various sources
  $competitors = [];

  // Try to get from context directly
  if (!empty($context['competitors']) && is_array($context['competitors'])) {
    $competitors = $context['competitors'];
  }

  // Try to get from profile data
  if (empty($competitors) && !empty($context['profile'])) {
    $profile = $context['profile'];
    
    // Check for competitor analysis data
    if (!empty($profile['competitors']) && is_array($profile['competitors'])) {
      $competitors = array_column($profile['competitors'], 'domain');
    }
    
    // Check for competitor reports
    if (!empty($profile['competitor_reports']) && is_array($profile['competitor_reports'])) {
      foreach ($profile['competitor_reports'] as $report) {
        if (!empty($report['domain']) && !in_array($report['domain'], $competitors, true)) {
          $competitors[] = $report['domain'];
        }
      }
    }
    
    // Check for competitive analysis data streams
    if (!empty($profile['data_streams']) && is_array($profile['data_streams'])) {
      foreach ($profile['data_streams'] as $stream) {
        if (!empty($stream['categories']) && in_array('competitive', $stream['categories'], true)) {
          if (!empty($stream['competitor_url'])) {
            $domain = preg_replace('/^https?:\/\//', '', $stream['competitor_url']);
            $domain = preg_replace('/^www\./', '', $domain);
            $domain = rtrim($domain, '/');
            $domain = strtolower($domain);
            if (!in_array($domain, $competitors, true)) {
              $competitors[] = $domain;
            }
          }
        }
      }
    }
  }

  // Also check the client's own domain
  $client_domain = '';
  if (!empty($context['profile']['home_url'])) {
    $client_domain = preg_replace('/^https?:\/\//', '', $context['profile']['home_url']);
    $client_domain = preg_replace('/^www\./', '', $client_domain);
    $client_domain = rtrim($client_domain, '/');
    $client_domain = strtolower($client_domain);
  }

  // Fetch VLDR data for all competitors
  $vldr_rows = [];
  
  // Always include client domain if available
  if (!empty($client_domain)) {
    $client_vldr = luna_vldr_get_score_from_hub($license_key, $client_domain);
    if ($client_vldr) {
      $vldr_rows[] = [
        'domain' => $client_vldr['domain'] ?? $client_domain,
        'vldr'   => isset($client_vldr['vldr_score']) ? (float) $client_vldr['vldr_score'] : 0.0,
        'asof'   => $client_vldr['metric_date'] ?? '',
        'ref'    => isset($client_vldr['ref_domains']) ? (int) $client_vldr['ref_domains'] : 0,
        'idx'    => isset($client_vldr['indexed_pages']) ? (int) $client_vldr['indexed_pages'] : 0,
        'lh'     => isset($client_vldr['lighthouse_avg']) ? (int) $client_vldr['lighthouse_avg'] : 0,
        'sec'    => $client_vldr['security_grade'] ?? 'N/A',
        'agey'   => isset($client_vldr['domain_age_years']) ? (float) $client_vldr['domain_age_years'] : 0.0,
        'up'     => isset($client_vldr['uptime_percent']) ? (float) $client_vldr['uptime_percent'] : 0.0,
        'is_client' => true,
      ];
    }
  }

  // Fetch VLDR for competitors
  foreach ($competitors as $domain) {
    if (empty($domain) || !is_string($domain)) {
      continue;
    }

    // Skip if already fetched (client domain)
    if ($domain === $client_domain) {
      continue;
    }

    $row = luna_vldr_get_score_from_hub($license_key, $domain);
    if ($row) {
      $vldr_rows[] = [
        'domain' => $row['domain'] ?? $domain,
        'vldr'   => isset($row['vldr_score']) ? (float) $row['vldr_score'] : 0.0,
        'asof'   => $row['metric_date'] ?? '',
        'ref'    => isset($row['ref_domains']) ? (int) $row['ref_domains'] : 0,
        'idx'    => isset($row['indexed_pages']) ? (int) $row['indexed_pages'] : 0,
        'lh'     => isset($row['lighthouse_avg']) ? (int) $row['lighthouse_avg'] : 0,
        'sec'    => $row['security_grade'] ?? 'N/A',
        'agey'   => isset($row['domain_age_years']) ? (float) $row['domain_age_years'] : 0.0,
        'up'     => isset($row['uptime_percent']) ? (float) $row['uptime_percent'] : 0.0,
        'is_client' => false,
      ];
    }
  }

  // Add VLDR data to context if available
  if (!empty($vldr_rows)) {
    $context['vldr'] = $vldr_rows;
    
    // Add human-readable summary for chat responses
    $context['vldr_summary'] = [];
    foreach ($vldr_rows as $row) {
      $summary = sprintf(
        'Domain: %s | VL-DR Score: %.1f (as of %s) | Referring domains: ~%s | Indexed pages: ~%s | Lighthouse: %d | Security: %s | Age: %.1f yrs | Uptime: %.2f%%',
        $row['domain'],
        $row['vldr'],
        $row['asof'] ? date('M j, Y', strtotime($row['asof'])) : 'N/A',
        $row['ref'] > 0 ? number_format($row['ref'] / 1000, 1) . 'k' : '0',
        $row['idx'] > 0 ? number_format($row['idx'] / 1000, 1) . 'k' : '0',
        $row['lh'],
        $row['sec'],
        $row['agey'],
        $row['up']
      );
      $context['vldr_summary'][] = $summary;
    }
    
    // Add transparency note
    $context['vldr_transparency'] = 'VL-DR (Visible Light Domain Ranking) is computed from public indicators: Common Crawl/Index, Bing Web Search, SecurityHeaders.com, WHOIS, Visible Light Uptime monitoring, and Lighthouse performance scores.';
  }

  return $context;
}, 10, 1);

/**
 * Enrich profile data with competitor analysis data for better context.
 */
add_filter('vl_hub_profile_resolved', function (array $profile, string $license_key): array {
  // Add competitor URLs from competitor settings if available
  if (!empty($license_key)) {
    $competitor_settings = get_option('vl_competitor_settings_' . $license_key, []);
    // Support both 'urls' (current) and 'competitor_urls' (legacy) for backwards compatibility
    $competitor_urls = [];
    if (!empty($competitor_settings['urls']) && is_array($competitor_settings['urls'])) {
      $competitor_urls = $competitor_settings['urls'];
    } elseif (!empty($competitor_settings['competitor_urls']) && is_array($competitor_settings['competitor_urls'])) {
      $competitor_urls = $competitor_settings['competitor_urls'];
    }
    
    if (!empty($competitor_urls)) {
      $profile['competitors'] = array_map(function($url) {
        $domain = preg_replace('/^https?:\/\//', '', $url);
        $domain = preg_replace('/^www\./', '', $domain);
        $domain = rtrim($domain, '/');
        return [
          'url' => $url,
          'domain' => strtolower($domain),
        ];
      }, array_filter($competitor_urls));
    }
    
    // Add performance metrics (Lighthouse/PageSpeed) if available
    $pagespeed_settings = get_option('vl_pagespeed_settings_' . $license_key, []);
    if (!empty($pagespeed_settings['analyses']) && is_array($pagespeed_settings['analyses'])) {
      $latest_analysis = end($pagespeed_settings['analyses']);
      if (is_array($latest_analysis)) {
        $profile['performance'] = [
          'lighthouse' => [
            'performance' => $latest_analysis['performance_score'] ?? 0,
            'accessibility' => $latest_analysis['accessibility_score'] ?? 0,
            'seo' => $latest_analysis['seo_score'] ?? 0,
            'best_practices' => $latest_analysis['best_practices_score'] ?? 0,
            'last_updated' => $latest_analysis['date'] ?? '',
          ],
        ];
      }
    }
    
    // Add SEO data (Search Console) if available
    $gsc_data = get_option('vl_gsc_data_' . $license_key, []);
    if (!empty($gsc_data) && is_array($gsc_data)) {
      $profile['seo'] = [
        'total_clicks' => 0,
        'total_impressions' => 0,
        'avg_ctr' => 0.0,
        'avg_position' => 0.0,
        'top_queries' => [],
      ];
      
      if (!empty($gsc_data['search_queries']) && is_array($gsc_data['search_queries'])) {
        $total_clicks = 0;
        $total_impressions = 0;
        $total_ctr = 0.0;
        $total_position = 0.0;
        $query_count = 0;
        
        foreach ($gsc_data['search_queries'] as $query) {
          $total_clicks += $query['clicks'] ?? 0;
          $total_impressions += $query['impressions'] ?? 0;
          $total_ctr += $query['ctr'] ?? 0.0;
          $total_position += $query['position'] ?? 0.0;
          $query_count++;
        }
        
        if ($query_count > 0) {
          $profile['seo']['total_clicks'] = $total_clicks;
          $profile['seo']['total_impressions'] = $total_impressions;
          $profile['seo']['avg_ctr'] = $total_ctr / $query_count;
          $profile['seo']['avg_position'] = $total_position / $query_count;
        }
        
        // Top 5 queries
        $top_queries = array_slice($gsc_data['search_queries'], 0, 5);
        $profile['seo']['top_queries'] = array_map(function($q) {
          return [
            'query' => $q['keys'][0] ?? '',
            'clicks' => $q['clicks'] ?? 0,
            'impressions' => $q['impressions'] ?? 0,
            'ctr' => ($q['ctr'] ?? 0.0) * 100,
            'position' => $q['position'] ?? 0.0,
          ];
        }, $top_queries);
      }
    }
    
    // Add data stream summary for better context
    // Use a helper function to get data streams safely
    $all_streams = get_option('vl_data_streams', []);
    if (!empty($all_streams[$license_key]) && is_array($all_streams[$license_key])) {
      $streams = $all_streams[$license_key];
      $profile['data_streams_summary'] = [
        'total' => count($streams),
        'by_category' => [],
        'active' => 0,
        'recent' => [],
      ];
      
      foreach ($streams as $stream_id => $stream) {
        if (!is_array($stream)) continue;
        
        if (!empty($stream['status']) && $stream['status'] === 'active') {
          $profile['data_streams_summary']['active']++;
        }
        
        if (!empty($stream['categories']) && is_array($stream['categories'])) {
          foreach ($stream['categories'] as $category) {
            if (!isset($profile['data_streams_summary']['by_category'][$category])) {
              $profile['data_streams_summary']['by_category'][$category] = 0;
            }
            $profile['data_streams_summary']['by_category'][$category]++;
          }
        }
        
        // Collect recent streams (last 5)
        if (!empty($stream['last_updated'])) {
          $profile['data_streams_summary']['recent'][] = [
            'id' => $stream_id,
            'name' => $stream['name'] ?? '',
            'category' => $stream['categories'][0] ?? '',
            'last_updated' => $stream['last_updated'],
          ];
        }
      }
      
      // Sort recent by last_updated descending
      usort($profile['data_streams_summary']['recent'], function($a, $b) {
        return strtotime($b['last_updated'] ?? '') <=> strtotime($a['last_updated'] ?? '');
      });
      
      $profile['data_streams_summary']['recent'] = array_slice($profile['data_streams_summary']['recent'], 0, 5);
    }
  }

  return $profile;
}, 10, 2);
