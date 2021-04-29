<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the
 * installation. You don't have to use the web site, you can
 * copy this file to "wp-config.php" and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * MySQL settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://wordpress.org/support/article/editing-wp-config-php/
 *
 * @package WordPress
 */

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'store' );

/** MySQL database username */
define( 'DB_USER', 'root' );

/** MySQL database password */
define( 'DB_PASSWORD', '' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

/**#@+
 * Authentication Unique Keys and Salts.
 *
 * Change these to different unique phrases!
 * You can generate these using the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}
 * You can change these at any point in time to invalidate all existing cookies. This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define( 'AUTH_KEY',         'i ejh?QaRS(@bHij5u>uLttivIxY*|VE|]SL)-FKXq,#0`7tkhvlN70cQLu:>EpZ' );
define( 'SECURE_AUTH_KEY',  '|eyuapsn_Y?A,ty)YM`%A0qKpa,6Y T1X_M``o;T{}38l^vSRuZ#LWyy|Ji{2=@k' );
define( 'LOGGED_IN_KEY',    '0XJQXUcmvS_/Hs/#m26 Ss}.A&GuULqt#@yd#PTNl5!Zb8c@?7f@Nh.PD0wsfZBE' );
define( 'NONCE_KEY',        'iw45~6Gt&%/6P<9_Isz=9d)u  E_ta.SbXEZU8$!2esh;p@t+AdmqZ$C2[z;cdNo' );
define( 'AUTH_SALT',        '[vn|D}xN-Uw_a0wNA&!Y9T_#gh|Hf`zPKfssE%/0U*XCi9|kibA)!z_IrGdYkOHw' );
define( 'SECURE_AUTH_SALT', ')Ll/z5&RbrMQ=fFt/Iyrg5 0UIHV8J[lO;KQAQT&g,G2=,uV=S)JWE{][JRCC|HM' );
define( 'LOGGED_IN_SALT',   'd@Yu5Rv~czc/{0{ ;-4_nHCM?EV9x!i~&i(2LLGT%jrpWYdE;r)W$:]n:~TTh34a' );
define( 'NONCE_SALT',       '3vy?INV uGD4ixjK$la@Sj[GsMHHP_U_K29v/./yso5$PXeN6FKd)iI0mMY=vKV!' );

/**#@-*/

/**
 * WordPress Database Table prefix.
 *
 * You can have multiple installations in one database if you give each
 * a unique prefix. Only numbers, letters, and underscores please!
 */
$table_prefix = 'swxqe_';

/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 *
 * For information on other constants that can be used for debugging,
 * visit the documentation.
 *
 * @link https://wordpress.org/support/article/debugging-in-wordpress/
 */
define( 'WP_DEBUG', false );

/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';
//Disable File Edits
define('DISALLOW_FILE_EDIT', true);