<?php
namespace ChopraSSO\SDK;

class Client
{
    /**
     * Contains client key parameter.
     *
     * @var string
     */
    protected $clientKey;

    /**
     * Contains client secret parameter.
     *
     * @var string
     */
    protected $clientSecret;

    /**
     * Contains api key parameter.
     *
     * @var string
     */
    protected $apiKey;

    /**
     * Contains session host parameter.
     *
     * @var string
     */
    protected $sessionHost;

    /**
     * Contains session port parameter.
     *
     * @var int
     */
    protected $sessionPort;

    /**
     * The algorithm used for encryption.
     *
     * @var string
     */
    protected $cipher = 'AES-256-CBC';

    /**
     * The block size of the cipher.
     *
     * @var int
     */
    protected $block = 16;

    /**
     * Contains the session connector object.
     *
     * @var null
     */
    protected $session;

    /**
     * Contains the API connector object.
     *
     * @var null
     */
    protected $api;

    /**
     * Contains live endpoint basepath to SSO Front site.
     *
     * @var string
     */
    protected $endpointBasePath = 'https://account.chopra.com/';

    /**
     * Contains SSO authentication endpoint path.
     *
     * @var string
     */
    protected $authEndpoint = 'auth';

    /**
     * Contains SSO social authentication endpoint path.
     *
     * @var string
     */
    protected $authSocialEndpoint = 'social/auth';

    /**
     * Contains SSO check request endpoint path.
     *
     * @var string
     */
    protected $checkEndpoint = 'check';

    /**
     * Contains SSO logout request endpoint path.
     *
     * @var string
     */
    protected $logoutEndpoint = 'logout';

    /**
     * Contains SSO user profile edit endpoint path.
     *
     * @var string
     */

    protected $profileEditEndpoint = 'user/profile/edit';

    /**
     * Contains API endpoint url.
     *
     * @var string
     */

    protected $apiEndpoint = 'https://account-api.chopra.com/';

    /**
     * Contains the user array
     *
     * @var array
     */
    protected $user;

    /**
     * Contains the generated cookie name
     *
     * @var string
     */
    protected $cookieName;

    /**
     * Contains the last exception thrown in getUser method
     *
     * @var \Exception
     */
    protected $lastException;

    /**
     * Contains how many times do we try to connect to memcache before throwing MemcachedException
     *
     * @var integer
     */
    protected $memcacheConnectTolerance = 3;

    /**
     * Initializes the SSO SDK Client object, and API / Session objects if needed.
     *
     * @param array $params Associative array with appropriate parameters for SSO connection.
     * @throws \Exception
     */
    public function __construct(Array $params)
    {
        if (count($diff = array_diff(['client_key', 'client_secret', 'session_host', 'session_port'],
                array_keys($params))) > 0
        ) {
            throw new \BadMethodCallException('Missing Chopra SDK parameters: ' . implode(", ", $diff));
        }

        $this->clientKey = $params['client_key'];
        $this->clientSecret = $params['client_secret'];

        $this->cookieName = 'chopra_sso_' . substr(md5($this->clientKey . $this->clientSecret), 0, 6);

        if (array_key_exists('endpoint_basepath', $params)) {
            $this->endpointBasePath = $params['endpoint_basepath'];
        }
        if (array_key_exists('session_host', $params) && array_key_exists('session_port', $params)) {
            $this->sessionHost = $params['session_host'];
            $this->sessionPort = $params['session_port'];
        }
        if (array_key_exists('api_key', $params)) {
            $this->apiKey = $params['api_key'];
        }
        if (array_key_exists('api_key', $params)) {
            $this->apiKey = $params['api_key'];
        }
        if (array_key_exists('api_endpoint', $params)) {
            $this->apiEndpoint = $params['api_endpoint'];
        }

    }

    /**
     * Get the host name for cookie
     *
     * @return string
     */
    protected function getBaseHttpHost()
    {
        if (array_key_exists('HTTP_X_FORWARDED_HOST', $_SERVER)) {
            $host = $_SERVER['HTTP_X_FORWARDED_HOST'];
        } else {
            $host = $_SERVER['HTTP_HOST'];
        }

        $segments = explode('.', $host);
        if (count($segments) < 2) {
            return $host;
        }
        return $segments[count($segments) - 2] . '.' . $segments[count($segments) - 1];
    }

    /**
     * Handles response from SSO Front site.
     *
     * @return bool
     */
    protected function handleSSOResponse()
    {
        setcookie($this->cookieName, $_GET['sso_code'], time() + 31556926, '/', '.' . $this->getBaseHttpHost());
        $_COOKIE[$this->cookieName] = $_GET['sso_code'];
    }

    /**
     * Retreives user from session, or throws exception if there is no user data.
     * This user data can be guest session data too, Not necessary to be logged in member user.
     *
     * @return mixed
     * @throws SSOAuthException
     */
    public function getUser()
    {
        $this->user = null;
        if (array_key_exists('sso_code', $_GET)) {
            $this->handleSSOResponse();
        }

        try {
            $data = $this->getCookieData();
            $this->user = $this->getSessionUser($data);
        } catch (\Exception $e) {
            $e = $this->handleException($e);
            $this->setLastException($e);
            throw $e;
        }

        return $this->user;
    }

    /**
     * Get user from session
     *
     * @param $data
     * @return mixed
     * @throws SSOAuthException
     */
    protected function getSessionUser($data)
    {
        $this->session()->setId($data['sso_id']);

        $user = $this->session()->get('user');
        if (!is_array($user) && !is_object($user)) {
            throw new SSOAuthException('Can\'t retrieve user data from session.', SSOAuthException::ERROR_SESSION);
        }

        // if user in session other than user in cookie
        if (($user['_auth_type'] == 'guest' && (array_key_exists('u_id', $data) || array_key_exists('api_token',
                        $data))) ||
            ($user['_auth_type'] == 'member' && (!array_key_exists('u_id', $data) || !array_key_exists('api_token',
                        $data) || $user['id'] !== $data['u_id']))
        ) {
            throw new SSOAuthException('User changed.', SSOAuthException::ERROR_USER_CHANGED);
        }

        if (array_key_exists('api_token', $data) && $this->api()) {
            $this->api()->setToken($data['api_token']);
        }

        return $user;
    }

    /**
     * Decrypt cookie data if cookie exists
     *
     * @return mixed
     * @throws SSOAuthException
     */
    protected function getCookieData()
    {
        if (!array_key_exists($this->cookieName, $_COOKIE)) {
            throw new SSOAuthException('No cookie', SSOAuthException::ERROR_NO_COOKIE);
        }
        $decrypted = $this->decryptCode($_COOKIE[$this->cookieName]);

        if (false === $decrypted) {
            throw new SSOAuthException('Can\'t decrypt cookie.', SSOAuthException::ERROR_DECRYPT);
        }

        $data = unserialize($decrypted);

        return $data;
    }

    /**
     * Handles exceptions thrown by getUser method.
     * Controls the sdk to not get in a redirect loop
     * if memcached connect failed.
     *
     * @param \Exception $e
     * @return SSOAuthException|\Exception
     */
    protected function handleException(\Exception $e)
    {
        if ($e instanceof \MemcachedException) {
            if ($this->getErrorCounter() < $this->memcacheConnectTolerance) {
                $e = new SSOAuthException('Memcache error occurred: ' . $e->getMessage(), $e->getCode(), $e);
            } else {
                $this->incrementErrorCounter();
            }
        }

        return $e;
    }

    /**
     * Increment error counter for exception handler
     */
    protected function incrementErrorCounter()
    {
        $_COOKIE[$this->cookieName . '_c']++;
        setcookie($this->cookieName . '_c', $_COOKIE[$this->cookieName . '_c'], time() + 300, '/',
            '.' . $this->getBaseHttpHost());
    }

    /**
     * Get error counter 
     *
     * @return mixed
     */
    protected function getErrorCounter()
    {
        if (!array_key_exists($this->cookieName . '_c', $_COOKIE)) {
            setcookie($this->cookieName . '_c', 0, time() + 300, '/', '.' . $this->getBaseHttpHost());
            $_COOKIE[$this->cookieName . '_c'] = 0;
        }

        return $_COOKIE[$this->cookieName . '_c'];
    }

    /**
     * Last Exception property setter.
     *
     * @param \Exception $e
     */
    protected function setLastException(\Exception $e)
    {
        $this->lastException = $e;
    }

    /**
     * Checks whether if authenticated user session exists, or just guest session.
     *
     * @return bool
     * @throws \Exception
     */
    public function memberLoggedIn()
    {
        if (null === $this->user) {
            throw new \Exception('Invalid method call: memberLoggedIn method was called without successful session validation!');
        }
        $user = $this->session()->get('user');

        return is_array($user) && array_key_exists('_auth_type', $user) && $user['_auth_type'] == 'member';
    }

    /**
     * Returns the session instance.
     *
     * @return bool
     */
    public function session()
    {
        if (!$this->session instanceof Session && $this->sessionHost && $this->sessionPort) {
            $this->session = new Session([
                'memcache_host' => $this->sessionHost,
                'memcache_port' => $this->sessionPort
            ]);
        }

        return $this->session ?: false;
    }

    /**
     * Returns the API instance.
     *
     * @return bool
     */
    public function api()
    {
        if (!$this->api instanceof Api && $this->apiKey) {
            $this->api = new Api([
                'client_key' => $this->clientKey,
                'api_key' => $this->apiKey,
                'api_endpoint' => $this->apiEndpoint
            ]);
        }

        return $this->api ?: false;
    }

    /**
     * Encrypts social token for secure transfer.
     *
     * @param $token
     * @return string
     */
    protected function encryptSocialToken($token)
    {
        $iv = openssl_random_pseudo_bytes(16);
        $value = openssl_encrypt(serialize($token), $this->cipher, $this->clientSecret, 0, $iv);
        $mac = hash_hmac('sha256', ($iv = base64_encode($iv)) . $value, $this->clientSecret);

        return base64_encode(json_encode(compact('iv', 'value', 'mac')));
    }

    /**
     * Decrypts SSO code got from SSO Front site after login.
     *
     * @param $code
     * @return mixed
     */
    protected function decryptCode($code)
    {
        $payload = json_decode(base64_decode($code), true);
        $iv = base64_decode($payload['iv']);
        $decrypted = openssl_decrypt($payload['value'], $this->cipher, $this->clientSecret, 0, $iv);

        return unserialize($decrypted);
    }

    /**
     * Returns SSO Simple Login url.
     *
     * @param $redirect_url Full qualified url to redirect back after successful login.
     * @return string
     */
    public function getLoginUrl($redirect_url)
    {
        return $this->endpointBasePath . $this->authEndpoint . '?client_key=' . $this->clientKey . '&redirect_url=' . urlencode($redirect_url);
    }

    /**
     * Returns SSO Check url.
     *
     * @param $redirect_url Full qualified url to redirect back after checking cookie on SSO side.
     * @return string
     */
    public function getCheckUrl($redirect_url)
    {
        $reasonCode = (null !== $this->lastException->getPrevious() && $this->lastException->getPrevious() instanceof \MemcachedException ? 'mc_' : '') . ($this->lastException ? $this->lastException->getCode() : '');
        return $this->endpointBasePath . $this->checkEndpoint . '?client_key=' . $this->clientKey . '&redirect_url=' . urlencode($redirect_url) . '&reason_code=' . $reasonCode;
    }

    /**
     * Returns SSO Logout url.
     *
     * @param $redirect_url Full qualified url to redirect back after successful logout.
     * @return string
     */
    public function getLogoutUrl($redirect_url)
    {
        return $this->endpointBasePath . $this->logoutEndpoint . '?redirect_url=' . urlencode($redirect_url);
    }

    /**
     * Returns SSO Social Login url.
     *
     * @param $redirect_url Full qualified url to redirect back after successful login.
     * @return string
     */
    public function getSocialLoginUrl($redirect_url, $social_type, Array $social_data)
    {
        return $this->endpointBasePath . $this->authSocialEndpoint . '?client_key=' . $this->clientKey . '&redirect_url=' . urlencode($redirect_url) . '&social_type=' . $social_type . '&social_id=' . $social_data['id'] . '&social_token=' . $this->encryptSocialToken($social_data['token']);
    }

    /**
     * Returns SSO Profile edit url.
     *
     * @param $redirect_url Full qualified url to redirect back after editing profile.
     * @return string
     */
    public function getProfileEditUrl($redirect_url)
    {
        return $this->endpointBasePath . $this->profileEditEndpoint . '?client_key=' . $this->clientKey . '&redirect_url=' . urlencode($redirect_url);
    }

    /**
     * $apiKey setter.
     *
     * @param string $key
     */
    public function setApiKey($key)
    {
        $this->apiKey = $key;
    }

}

class SSOAuthException extends \Exception
{
    const ERROR_NO_COOKIE = 1;
    const ERROR_DECRYPT = 2;
    const ERROR_SESSION = 3;
    const ERROR_USER_CHANGED = 4;
}
