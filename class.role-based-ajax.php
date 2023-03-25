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
	 * Adds a ajax action hook if the current user has the required role.
	 *
	 * @uses wp_get_current_user()
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
		
		if ( ! function_exists( 'wp_create_nonce' ) ) {
			require_once ABSPATH . '/wp-includes/pluggable.php';
		}
		
		$current_user = \wp_get_current_user();
		
		if ( ! $current_user->exists() ) {
			$current_user_roles = array();
		} else {
			$wp_user_roles = $current_user->roles;
			$implicit_user_roles = $this->get_implicit_roles_for( $wp_user_roles );
			$current_user_roles =  \array_merge( $current_user->roles, $implicit_user_roles );
		}

		/* Use this filter to customize the current user roles at runtime. */
		$current_user_roles = \apply_filters( 'role_based_ajax_customize_roles', $current_user_roles );

		if ( 'all' === $role ) {
			$all_users = true;
		}

		$full_action_hook = "{$hook_prefix}{$action_hook}";
		$full_nopriv_action_hook = "{$hook_prefix}nopriv_{$action_hook}";
		$action_added = false;
		if ( $all_users || in_array( $role , $current_user_roles ) ) {
			\add_action( $full_action_hook, $callback );
			$action_added = true;
		}

		$nopriv_action_added = false;
		if ( $all_users ) {
			\add_action( $full_nopriv_action_hook, $callback );
			$nopriv_action_added = true;
		}

		/* Adds high priority action hooks for catching nonce checks. */
		if ( $this->auto_nonce_check ) {

			if ( $action_added ) { 
				\add_action(
					$full_action_hook,
					function() {
						$action_hook = $_REQUEST['action'];
						\check_ajax_referer( $action_hook );
					},
					1
				);
			}

			if ( $all_users && $nopriv_action_added ) {
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

	/**
	 * Extends the default wp user roles array
	 * 
	 * @param Array $user_roles
	 * @return Array
	 * 
	 */
	private function get_implicit_roles_for( Array $user_roles ) {

		if ( empty( $user_roles ) ) {
			return array();
		}

		$roles_map = array(
			'super_admin' => 5,
			'administrator' => 4,
			'editor' => 3,
			'author' => 2,
			'contributor' => 1,
			'subscriber' => 0
		);

		$role = '';
		$roles_number = 0;
		foreach ( $roles_map as $default_wp_role => $default_roles_number ) {

			if ( \in_array( $default_wp_role, $user_roles ) ) {
				$role = $default_wp_role;
				$roles_number = $default_roles_number;
				break;
			}

		}

		if ( ! isset( $roles_map[$role] ) ) {
			return array();
		}

		$allowed_roles = \array_slice(
			$roles_map, -($roles_number+1), $roles_number+1
		);

		return \array_keys(
			$allowed_roles
		);

	}

	public function add_for_all( String $action_hook, String $callback ) {
		return $this->add_for( $action_hook, $callback, 'all' );
	}

	public function add_for_subscriber( String $action_hook, String $callback ) {
		return $this->add_for( $action_hook, $callback, 'subscriber' );
	}

	public function add_for_contributor( String $action_hook, String $callback ) {
		return $this->add_for( $action_hook, $callback, 'contributor' );
	}

	public function add_for_author( String $action_hook, String $callback ) {
		return $this->add_for( $action_hook, $callback, 'author' );
	}

	public function add_for_editor( String $action_hook, String $callback ) {
		return $this->add_for( $action_hook, $callback, 'editor' );
	}

	public function add_for_admin( String $action_hook, String $callback ) {
		return $this->add_for( $action_hook, $callback, 'administrator' );
	}

	public function add_for_super_admin( String $action_hook, String $callback ) {
		return $this->add_for( $action_hook, $callback, 'super_admin' );
	}

	public function set_auto_nonce( bool $auto_nonce_check ) {
		$this->auto_nonce_check = $auto_nonce_check;
	}

	public function get_auto_nonce() {
		return $this->auto_nonce_check;
	}

}
