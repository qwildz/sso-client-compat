<?php

namespace Qwildz\SSOClient;

class SSOClient
{
    static private $config = array(
        'client_id' => '',
        'client_secret' => '',
        'endpoint' => '',
        'home' => '',
    );

    static public function setConfig($config)
    {
        static::$config = $config;
    }

    static public function handleLogin() {
        $isSecure = false;
        if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] == 'on') {
            $isSecure = true;
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] == 'https'
            || !empty($_SERVER['HTTP_X_FORWARDED_SSL']) && $_SERVER['HTTP_X_FORWARDED_SSL'] == 'on') {
            $isSecure = true;
        }
        $REQUEST_PROTOCOL = $isSecure ? 'https://' : 'http://';

        if(static::get('code')) {
            // Verify the state matches our stored state
            if(!static::get('state') || $_SESSION['state'] != static::get('state')) {
                header('Location: ' . $_SERVER['PHP_SELF']);
                die();
            }
            // Exchange the auth code for a token
            $token = static::apiRequest(static::$config['endpoint'].'/oauth/token', array(
                'client_id' => static::$config['client_id'],
                'client_secret' => static::$config['client_secret'],
                'redirect_uri' => $REQUEST_PROTOCOL . $_SERVER['SERVER_NAME'] . $_SERVER['PHP_SELF'],
                'state' => $_SESSION['state'],
                'code' => static::get('code'),
                'grant_type' => 'authorization_code'
            ));

            $_SESSION['access_token'] = $token->access_token;

            if(static::session('access_token')) {
                $user = static::apiRequest(static::$config['endpoint'].'/api/user');

                static::apiRequest(static::$config['endpoint'].'/session/set-sid', array(
                    'sid' => session_id(),
                ));

                return $user;
            } else {
                header('Location: '.self::$config['home']);
                die();
            }
        } else {
            // Start the login process by sending the user to Github's authorization page
            // Generate a random hash and store in the session for security
            $_SESSION['state'] = hash('sha256', microtime(TRUE).rand().$_SERVER['REMOTE_ADDR']);
            unset($_SESSION['access_token']);
            $params = array(
                'response_type' => 'code',
                'client_id' => static::$config['client_id'],
                'redirect_uri' => $REQUEST_PROTOCOL . $_SERVER['SERVER_NAME'] . $_SERVER['PHP_SELF'],
                'scope' => '*',
                'state' => $_SESSION['state']
            );

            // Redirect the user to Github's authorization page
            header('Location: ' . static::$config['endpoint'] . '/oauth/authorize?' . http_build_query($params));
            die();
        }
    }

    static public function handleLogout()
    {
        $logoutToken = $_POST['token'];

        $token = new Token();
        $token->parse($logoutToken);
        $claims = $token->getClaims();

        if ((!$token->verify(static::$config['client_secret']) || !self::validateLogoutToken($claims))
            || (!$token->hasClaim('sid'))
            || (!$token->hasClaim('events'))
            || (!array_key_exists('http://schemas.openid.net/event/backchannel-logout', (array)$claims['events']))
            || ($token->hasClaim('nonce'))) {
            static::badRequest();
        }

        if (session_id() == '') {
            session_id($claims['sid']);
            session_start();
        } else {
            session_id($claims['sid']);
        }

        $_SESSION = array();
        session_destroy();
        session_regenerate_id(true);

        echo 200;
    }

    static private function apiRequest($url, $post = false, $headers = array())
    {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CAINFO, dirname(__FILE__) . DIRECTORY_SEPARATOR . 'cacert.pem');

        if ($post) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($post));
        }

        $headers[] = 'Accept: application/json';
        if (static::session('access_token')) {
            $headers[] = 'Authorization: Bearer ' . static::session('access_token');
        }

        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        $response = curl_exec($ch);

        return json_decode($response);
    }

    static private function get($key, $default = NULL)
    {
        return array_key_exists($key, $_GET) ? $_GET[$key] : $default;
    }

    static private function session($key, $default = NULL)
    {
        return array_key_exists($key, $_SESSION) ? $_SESSION[$key] : $default;
    }

    static private function validateLogoutToken($claims)
    {
        return (
            hash_equals(static::$config['endpoint'], $claims['iss'])
            && hash_equals(static::$config['client_id'], $claims['aud'])
            && ((time() - 30) <= $claims['iat'] && $claims['iat'] <= (time() + 30))
        );
    }

    static private function badRequest()
    {
        header('HTTP/1.1 400 Bad Request');
        echo 'Bad Request';
        exit();
    }
}