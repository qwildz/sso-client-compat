<?php

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
        self::$config = $config;
    }

    static public function handleLogin() {
        if (session_id() == '') {
            session_start();
        }

        $isSecure = false;
        if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] == 'on') {
            $isSecure = true;
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] == 'https'
            || !empty($_SERVER['HTTP_X_FORWARDED_SSL']) && $_SERVER['HTTP_X_FORWARDED_SSL'] == 'on') {
            $isSecure = true;
        }
        $REQUEST_PROTOCOL = $isSecure ? 'https://' : 'http://';

        if(self::get('code')) {
            // Verify the state matches our stored state
            if(!self::get('state') || $_SESSION['state'] != self::get('state')) {
                header('Location: ' . $_SERVER['PHP_SELF']);
                die();
            }
            // Exchange the auth code for a token
            $token = self::apiRequest(self::$config['endpoint'].'/oauth/token', array(
                'client_id' => self::$config['client_id'],
                'client_secret' => self::$config['client_secret'],
                'redirect_uri' => $REQUEST_PROTOCOL . $_SERVER['SERVER_NAME'] . $_SERVER['PHP_SELF'],
                'state' => $_SESSION['state'],
                'code' => self::get('code'),
                'grant_type' => 'authorization_code'
            ));

            $_SESSION['access_token'] = $token->access_token;

            if(self::session('access_token')) {
                session_regenerate_id();

                $user = self::apiRequest(self::$config['endpoint'].'/api/user');

                self::apiRequest(self::$config['endpoint'].'/session/set-sid', array(
                    'sid' => session_id(),
                ));

                return $user;
            } else {
                header('Location: '.self::$config['home']);
                die();
            }
        } else {
            // Generate a random hash and store in the session for security
            $_SESSION['state'] = hash('sha256', microtime(TRUE).rand().$_SERVER['REMOTE_ADDR']);
            unset($_SESSION['access_token']);
            $params = array(
                'response_type' => 'code',
                'client_id' => self::$config['client_id'],
                'redirect_uri' => $REQUEST_PROTOCOL . $_SERVER['SERVER_NAME'] . $_SERVER['PHP_SELF'],
                'scope' => '*',
                'state' => $_SESSION['state']
            );

            // Redirect the user to Github's authorization page
            header('Location: ' . self::$config['endpoint'] . '/oauth/authorize?' . http_build_query($params));
            die();
        }
    }

    static public function logout()
    {
        if($token = self::session('access_token')) {
            self::apiRequest(self::$config['endpoint'].'/session/'.$token, false, array(), 'DELETE');
        }
    }

    static public function handleLogout()
    {
        $logoutToken = $_POST['token'];

        $token = new Token();
        $token->parse($logoutToken);
        $claims = $token->getClaims();

        if ((!$token->verify(self::$config['client_secret']) || !self::validateLogoutToken($claims))
            || (!$token->hasClaim('sid'))
            || (!$token->hasClaim('events'))
            || (!array_key_exists('http://schemas.openid.net/event/backchannel-logout', (array)$claims['events']))
            || ($token->hasClaim('nonce'))) {
            self::badRequest();
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

    static private function apiRequest($url, $post = false, $headers = array(), $method = null)
    {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CAINFO, dirname(__FILE__) . DIRECTORY_SEPARATOR . 'cacert.pem');

        if($method) {
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        }

        if ($post) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($post));
        }

        $headers[] = 'Accept: application/json';
        if (self::session('access_token')) {
            $headers[] = 'Authorization: Bearer ' . self::session('access_token');
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
            hash_equals(self::$config['endpoint'], $claims['iss'])
            && hash_equals(self::$config['client_id'], $claims['aud'])
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