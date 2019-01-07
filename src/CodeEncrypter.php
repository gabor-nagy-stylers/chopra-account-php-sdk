<?php
namespace ChopraSSO\SDK;

class CodeEncrypter {

    /**
     * The algorithm used for encryption.
     *
     * @var string
     */
    protected $cipher = 'AES-256-CBC';

    /**
     * Contains client secret parameter.
     *
     * @var string
     */
    protected $clientSecret;

    public function __construct($clientSecret)
    {
        $this->clientSecret = $clientSecret;
    }

    /**
     * Encrypts social token for secure transfer.
     *
     * @param $token
     * @return string
     */
    public function encryptSocialToken($token)
    {
        return $this->encryptData($token);
    }

    /**
     * Encrypts data for secure transfer.
     *
     * @param $data
     * @return string
     */
    public function encryptData($data)
    {
        $iv = openssl_random_pseudo_bytes(16);
        $value = openssl_encrypt(serialize($data), $this->cipher, $this->clientSecret, 0, $iv);
        $mac = hash_hmac('sha256', ($iv = base64_encode($iv)) . $value, $this->clientSecret);

        return base64_encode(json_encode(compact('iv', 'value', 'mac')));
    }

    /**
     * Decrypts SSO code got from SSO Front site after login.
     *
     * @param $code
     * @return mixed
     * @throws SSOAuthException
     */
    public function decryptCode($code)
    {
        $payload = json_decode(base64_decode($code), true);

        if (! $this->validPayload($payload)) {
            throw new SSOAuthException('The payload is invalid.', SSOAuthException::ERROR_DECRYPT);
        }

        if (! $this->validMac($payload)) {
            throw new SSOAuthException('The MAC is invalid.', SSOAuthException::ERROR_DECRYPT);
        }

        $iv = base64_decode($payload['iv']);
        $decrypted = openssl_decrypt($payload['value'], $this->cipher, $this->clientSecret, 0, $iv);

        return unserialize($decrypted);
    }

    /**
     * Verify that the encryption payload is valid.
     *
     * @param  mixed  $payload
     * @return bool
     */
    protected function validPayload($payload)
    {
        return is_array($payload) && isset($payload['iv'], $payload['value'], $payload['mac']);
    }

    /**
     * Determine if the MAC for the given payload is valid.
     *
     * @param  array $payload
     * @return bool
     * @throws \Exception
     */
    protected function validMac(array $payload)
    {
        $bytes = random_bytes(16);

        $calcMac = hash_hmac('sha256', $this->hash($payload['iv'], $payload['value']), $bytes, true);

        return hash_equals(hash_hmac('sha256', $payload['mac'], $bytes, true), $calcMac);
    }

    /**
     * Create a MAC for the given value.
     *
     * @param  string  $iv
     * @param  mixed  $value
     * @return string
     */
    protected function hash($iv, $value)
    {
        return hash_hmac('sha256', $iv.$value, $this->clientSecret);
    }
}