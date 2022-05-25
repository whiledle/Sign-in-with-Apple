<?php

require_once 'lib/Functions.php';

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Serializer\CompactSerializer;

function apple_auth() {
    require_once 'vendor/autoload.php';

    $algorithmManager = new AlgorithmManager([new ES256()]);
    $jwsBuilder = new JWSBuilder($algorithmManager);
    $serializer = new CompactSerializer();
    $func = new Functions;

    global $wpdb;

    $teamId = 'XXXXXXXXXX';
	$clientId = 'ru.YOUR_HOSTNAME.web';
	$code = $_POST['code'];
	$keyFileId = 'YYYYYYYYYY';
	$keyFileName = 'https://YOUR_HOSTNAME.ru/wp-content/themes/tspace/AuthKey_' . $keyFileId . '.p8';
	$redirectUri = 'https://YOUR_HOSTNAME.ru/signin';

    $jws = $jwsBuilder
	->create()
	->withPayload(json_encode([
		'iat' => time(),
		'exp' => time() + 3600,
		'iss' => $teamId,
		'aud' => 'https://appleid.apple.com',
		'sub' => $clientId
	]))
	->addSignature(JWKFactory::createFromKeyFile($keyFileName), [
		'alg' => 'ES256',
		'kid' => $keyFileId
	])
	->build();

    $token = $serializer->serialize($jws, 0);

    $data = [
		'client_id' => $clientId,
		'client_secret' => $token,
		'code' => $code,
		'grant_type' => 'authorization_code',
		'redirect_uri' => $redirectUri
	];

    $curlAction = curl_init();
	curl_setopt_array ($curlAction, [
		CURLOPT_URL => 'https://appleid.apple.com/auth/token',
		CURLOPT_POSTFIELDS => http_build_query($data),
		CURLOPT_RETURNTRANSFER => true
	]);
	$response = curl_exec($curlAction);
	curl_close ($curlAction);

    $response = json_decode($response);

    if(!isset($response->access_token)) {
		die('702');
	}

    $claims = explode('.', $response->id_token)[1];
	$claims = json_decode(base64_decode($claims));

    $userid = $claims->sub;
	$check_a_code = $wpdb->get_row("SELECT user_id FROM wp_usermeta WHERE meta_key = 'user_a_sub' AND meta_value = '$userid'");

    // Checking whether a user with this user_id exists
    if ( $check_a_code == NULL ) {
		$user_email = $claims->email;
		$check_exist_email = $wpdb->get_row("SELECT ID FROM wp_users WHERE user_email = '$user_email'");

        // Checking the existence of a user with this email
		if ( $check_exist_email == NULL ) { // Registering a new user
			if ( isset($_POST['first_name']) && $_POST['first_name'] != '' && isset($_POST['last_name']) && $_POST['last_name'] != '' ) {
				$user_first_name = $func->cleanerVar($_POST['first_name']);
				$user_last_name = $func->cleanerVar($_POST['last_name']);
			}
			$user_password =  $claims->sub;
			$user_login = $claims->email;
			$user_ip = $_SERVER['REMOTE_ADDR'];
			$user_balance = 0;
			$user_quantity_license = 0;

			if ( $user_first_name != '' && $user_last_name != '' ) {
				$userdata = array (
					'user_pass'		=> $user_password,
					'user_login'	=> $user_email,
					'user_email'	=> $user_email,
					'first_name'	=> $user_first_name,
					'last_name'		=> $user_last_name,
				);
			} else {
				$userdata = array (
					'user_pass'		=> $user_password,
					'user_login'	=> $user_email,
					'user_email'	=> $user_email,
				);
			}

			$user_id = wp_insert_user($userdata);

			add_user_meta($user_id, 'user_ip', $user_ip);
			add_user_meta($user_id, 'user_balance', $user_balance);
			add_user_meta($user_id, 'user_quantity_license', $user_quantity_license);
			add_user_meta($user_id, 'user_password', $user_password);
			add_user_meta($user_id, 'user_a_sub', $userid);
			add_user_meta($user_id, 'user_test_status', 'not_activated');

			$userdata = array (
				'user_login'	=> $user_email,
				'user_password'	=> $user_password,
				'remember'		=> false,
			);
			$user = wp_signon($userdata, false);

			if ( is_wp_error($user) ) {
				die('701');
			}
			die('200');
		} else {
            // email has already been registered
			die('703');
		}
	} else { // Authorize the user
		$userdata = array (
			'user_login'	=> $claims->email,
			'user_password'	=> $claims->sub,
			'remember'		=> false,
		);
		$user = wp_signon($userdata, false);
		if ( is_wp_error($user) ) {
			die('701');
		}
		echo '200';
        die();
	}
}

?>
