<?php
namespace ChopraSSO\SDK;

class Api
{
    protected $clientKey;
    protected $apiKey;
    protected $token;

    protected $apiEndpoint = 'https://account-api.chopra.com/';

    /**
     * Api constructor.
     * @param array $params
     */
    public function __construct(Array $params)
    {
        if (count($diff = array_diff(['client_key', 'api_key'], array_keys($params))) > 0) {
            throw new \BadMethodCallException('Missing Chopra SDK API parameters: ' . implode(", ", $diff));
        }

        $this->clientKey = $params['client_key'];
        $this->apiKey = $params['api_key'];
        if (array_key_exists('api_endpoint', $params) && $params['api_endpoint']) {
            $this->apiEndpoint = $params['api_endpoint'];
        }
    }

    /**
     * Make a call to api endpoint
     *
     * @param $uri
     * @param string $method
     * @param array $getParams
     * @param array $postParams
     * @param array $extraHeader
     * @return mixed
     */
    public function makeCall(
        $uri,
        $method = 'GET',
        Array $getParams = [],
        Array $postParams = [],
        Array $extraHeader = []
    ) {
        $postData = json_encode($postParams);
        $curl = curl_init($this->apiEndpoint . $uri . http_build_query($getParams));

        $headers = [
            'Accept: application/json',
            'Content-Type: application/json',
            'Content-Length: ' . strlen($postData),
            'X-SSO-ClientKey: ' . $this->clientKey,
            'X-SSO-ApiKey: ' . $this->apiKey
        ];

        if ($this->token) {
            $headers[] = 'Authorization: Bearer ' . $this->token;
        }

        curl_setopt_array($curl, [
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_POSTFIELDS => $postData,
            CURLOPT_HTTPHEADER => $headers
        ]);

        $result = curl_exec($curl);

        $decoded = json_decode($result);

        return $decoded;
    }

    /**
     * Set API token
     *
     * @param $token
     */
    public function setToken($token)
    {
        $this->token = $token;
    }

    /**
     * Get API token
     *
     * @return mixed
     */
    public function getToken()
    {
        return $this->token;
    }
}