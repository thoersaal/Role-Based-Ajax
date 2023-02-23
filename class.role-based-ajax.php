<?php
namespace RoleBasedAjax;

class RoleBasedAjax {
	
	private $auto_nonce_check;

	public function __construct( bool $auto_nonce_check=false, bool $set_it_global=true ) {

		$this->auto_nonce_check = $auto_nonce_check;

		if ( $set_it_global ) {
			$GLOBALS['rba'] = $this;
		}

		return $this;

	}


	/**
	 * Adds a ajax action hook if the current user has the required role or capability.
	 *
	 * Attention: This function uses the standard WordPress capabilities to determine if the
	 * hook should be added for the current user. This function may not work properly, 
	 * if the default wordpress capabilities are changed.
	 *
	 * @uses wp_get_current_user()
	 * @uses current_user_can()
	 * @uses add_action()
	 * @uses check_ajax_referer()
	 * @uses wp_create_nonce()
	 * @uses apply_filters()
	 *
	 * @param String $action_hook
	 * @param String $callback
	 * @param String $role
	 *
	 * @return String - WordPress Nonce
	 */
	public function add_for( String $action_hook, String $callback, String $role) {

		$role = strtolower( $role );
		$all_users = false;
		$hook_prefix = 'wp_ajax_';
		$capability = 'manage_options';
		$current_user_roles = array();

		if ( ! function_exists( 'wp_create_nonce' ) ) {
			require_once ABSPATH . '/wp-includes/pluggable.php';
		}

		switch ( $role ) {
			case 'all':
				$all_users = true;
				break;
			case 'subscriber':
				$capability = 'read';
				break;
			case 'contributor':
				$capability = 'edit_posts';
				break;
			case 'author':
				$capability = 'upload_files';
				break;
			case 'editor':
				$capability = 'unfiltered_html';
				break;
			case 'super_admin':
				$capability = 'setup_network';
				break;
			case 'administrator':
				$capability = 'manage_options';
				break;
			default:

				/* Handles non default WordPress roles */
				$current_user = \wp_get_current_user();

				if ( ! $current_user->exists() ) {
					$capability = 'manage_options';
				} else {
					$current_user_roles = $current_user->roles;
				}

				/* Use this filter to customize the current user roles at runtime. */
				$current_user_roles = \apply_filters( 'role_based_ajax_customize_roles', $current_user_roles );

				break;
		}

		$full_action_hook = "{$hook_prefix}{$action_hook}";
		$full_nopriv_action_hook = "{$hook_prefix}nopriv_{$action_hook}";
		if ( $all_users || in_array( $role , $current_user_roles ) || \current_user_can( $capability ) ) {
			\add_action( $full_action_hook, $callback );
		}

		if ( $all_users ) {
			\add_action( $full_nopriv_action_hook, $callback );
		}

		/* Adds high priority action hooks for catching nonce checks. */
		if ( $this->auto_nonce_check ) {

			\add_action(
				$full_action_hook,
				function() {
					$action_hook = $_REQUEST['action'];
					\check_ajax_referer( $action_hook );
				},
				1
			);

			if ( $all_users ) {
				\add_action(
					$full_nopriv_action_hook,
					function() {
						$action_hook = $_REQUEST['action'];
						\check_ajax_referer( $action_hook );
					},
					1
				);
			}

		}

		return \wp_create_nonce( $action_hook );

	}

	public function add_for_all( String $action_hook, String $callback ) {
		$this->add_for( $action_hook, $callback, 'all' );
	}

	public function add_for_subscriber( String $action_hook, String $callback ) {
		$this->add_for( $action_hook, $callback, 'subscriber' );
	}

	public function add_for_contributor( String $action_hook, String $callback ) {
		$this->add_for( $action_hook, $callback, 'contributor' );
	}

	public function add_for_author( String $action_hook, String $callback ) {
		$this->add_for( $action_hook, $callback, 'author' );
	}

	public function add_for_editor( String $action_hook, String $callback ) {
		$this->add_for( $action_hook, $callback, 'editor' );
	}

	public function add_for_admin( String $action_hook, String $callback ) {
		$this->add_for( $action_hook, $callback, 'administrator' );
	}

	public function add_for_super_admin( String $action_hook, String $callback ) {
		$this->add_for( $action_hook, $callback, 'super_admin' );
	}

	public function set_auto_nonce( bool $auto_nonce_check ) {
		$this->auto_nonce_check = $auto_nonce_check;
	}

	public function get_auto_nonce() {
		return $this->auto_nonce_check;
	}

}