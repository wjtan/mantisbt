<?php

require_once( config_get( 'library_path' ) . 'phpass' . DIRECTORY_SEPARATOR . 'PasswordHash.php' );

/**
 * Connect to phpBB database
 */
function phpbb_dbconn(){
  $t_hostname = config_get( 'hostname' );
  $t_db_username = config_get( 'db_username' );
  $t_db_password = config_get( 'db_password' );
  $t_phpbb_database = config_get( 'phpbb_database' );
  $t_conn = new mysqli($t_hostname, $t_db_username, $t_db_password, $t_phpbb_database);
  
  // Check connection
  if (mysqli_connect_errno()) {
    log_event( LOG_PHPBB, 'Connection to phpbb database failed' );
    trigger_error( ERROR_DB_QUERY_FAILED, ERROR );
    return false;
  }

  return $t_conn;
}

/**
 * Attempt to authenticate the user via phpBB
 * return true on successful authentication, false otherwise
 * @param int $p_user_id
 * @param string $p_password
 * @return bool
 */
function phpbb_authenticate( $p_user_id, $p_password ) {
    $t_username = user_get_field( $p_user_id, 'username' );

    return phpbb_authenticate_by_username( $t_username, $p_password );
}


/**
 * Authenticates an user via phpBB given the username and password.
 *
 * @param string $p_username The user name.
 * @param string $p_password The password.
 * @return true: authenticated, false: failed to authenticate.
 */
function phpbb_authenticate_by_username( $p_username, $p_password ) {
  $t_conn = phpbb_dbconn();  
  if(!$t_conn){
    return false;
  }

  $t_phpbb_prefix = config_get( 'phpbb_prefix' );
  $t_username = $t_conn->real_escape_string(strtolower($p_username));
  $t_sql = 'SELECT user_password FROM ' . $t_phpbb_prefix . "users WHERE user_type <> 2 AND username_clean = '$t_username'";
  $t_result = $t_conn->query($t_sql);

  if (!$t_result) {
    log_event( LOG_PHPBB, 'No password hash for user ' . $p_username );
    $t_conn->close();
    return false;
  }
  
  $t_row = $t_result->fetch_row();
  $t_hash = $t_row[0];

  // Close connection
  $t_result->close();
  $t_conn->close();
  
  $t_check = phpbb_check_password($p_password, $t_hash);
  
  if($t_check){
    log_event( LOG_PHPBB, 'Hash check successful' );
  } else {
    log_event( LOG_PHPBB, 'Hash check failed' );
  }
  
  return $t_check;
}

$g_cache_phpbb_email = array();

/**
 * returns an email address from phpBB, given a userid
 * @param int $p_user_id
 * @return string
 */
function phpbb_email( $p_user_id ) {
  global $g_cache_phpbb_email;

  if( isset( $g_cache_phpbb_email[ (int)$p_user_id ] ) ) {
    return $g_cache_phpbb_email[ (int)$p_user_id ];
  }

  $t_username = user_get_field( $p_user_id, 'username' );
  $t_email = phpbb_email_from_username( $t_username );

  $g_cache_phpbb_email[ (int)$p_user_id ] = $t_email;
  return $t_email;
}

/**
 * Return an email address from phpBB, given a username
 * @param string $p_username
 * @return string
 */
function phpbb_email_from_username( $p_username ) {
  $t_conn = phpbb_dbconn();  
  if(!$t_conn){
    return '';
  }
  
  $t_phpbb_prefix = config_get( 'phpbb_prefix' );
  $t_username_clean = utf8_clean_string($p_username);
  $t_username = $t_conn->real_escape_string($t_username_clean);
  $t_sql = 'SELECT user_email FROM ' . $t_phpbb_prefix . "users WHERE user_type <> 2 AND username_clean = '$t_username'";
  $t_result = $t_conn->query($t_sql);

  if (!$t_result) {
    log_event( LOG_PHPBB, 'No email for user ' . $p_username );
    $t_conn->close();
    return false;
  }
  
  $t_row = $t_result->fetch_row();
  $t_email = $t_row[0];

  // Close connection
  $t_result->close();
  $t_conn->close();

  return $t_email;
}

function phpbb_check_password( $p_password, $p_hash ) {
  $t_prefix = substr( $p_hash, 0, 4 );

  if($t_prefix === '$2a$' || $t_prefix === '$2y$'){
    return bcrypt_check($p_password, $p_hash);
  } else {
    $t_hasher = new PasswordHash(8, FALSE);
    return $t_hasher->CheckPassword($p_password, $p_hash);
  }
}

function bcrypt_hash($password, $salt){
  $hash = crypt($password, $salt);
  if (strlen($hash) < 60)
  {
    return false;
  }
  return $hash;
}

function bcrypt_check($password, $hash){
  $salt = substr($hash, 0, 29);
  if (strlen($salt) != 29)
  {
    return false;
  }

  return (bcrypt_hash($password, $salt) === $hash);
}

