<?php
namespace ChopraSSO\SDK;

class Session
{
    protected $sessionPrefix = 'sso:';
    protected $sessionId;
    protected $memcachedHost;
    protected $memcachedPort = 11211;

    protected $connection;
    protected $data = [];

    /**
     * Session constructor.
     * @param $params
     */
    public function __construct(Array $params)
    {
        if (count($diff = array_diff(['memcache_host'], array_keys($params))) > 0) {
            throw new \BadMethodCallException('Missing Chopra Session SDK parameters: ' . implode(", ", $diff));
        }

        $this->memcachedHost = $params['memcache_host'];
        $this->memcachedPort = $params['memcache_port'];

        $this->connect();
    }

    /**
     * Create memcached connection instance.
     */
    public function connect()
    {
        $this->connection = new \Memcached('chopra_sso');
        $serverList = $this->connection->getServerList();

        $serverExists = false;
        foreach ($serverList as $server) {
            if ($server['host'] === $this->memcachedHost && $server['port'] === (int)$this->memcachedPort) {
                $serverExists = true;
            }
        }

        if (!$serverExists) {
            $this->connection->resetServerList();
            $res = $this->connection->addServer($this->memcachedHost, $this->memcachedPort);
            if (!$res) {
                throw new \MemcachedException('Can\'t connect to memcache server.');
            }
        }
        $this->connection->setOption(\Memcached::OPT_SERIALIZER, \Memcached::SERIALIZER_PHP);
    }

    /**
     * Get session id
     *
     * @return mixed
     */
    public function getId()
    {
        return $this->sessionId;
    }

    /**
     * Set session id
     *
     * @param $sessionId
     * @return $this
     * @throws \Exception
     */
    public function setId($sessionId)
    {
        if (null === $sessionId || !$sessionId) {
            throw new \InvalidArgumentException('SessionId must be a string.');
        }
        $this->sessionId = $sessionId;

        return $this;
    }

    /**
     * Get session item
     *
     * @param null $key
     * @return array|null
     * @throws \Exception
     */
    public function get($key = null)
    {
        if (null === $this->sessionId || !$this->sessionId) {
            throw new \InvalidArgumentException('Session id is not set up!');
        }

        $this->readSessionData();

        if (null === $key) {
            return $this->data;
        }

        if (is_array($this->data) && array_key_exists($key, $this->data)) {
            return $this->data[$key];
        }

        return null;
    }

    /**
     * Set session item
     *
     * @param $key
     * @param $value
     * @return $this
     */
    public function set($key, $value)
    {
        $this->readSessionData();

        $this->data[$key] = $value;

        $this->writeSessionData();

        return $this;
    }

    /**
     * Read session data
     */
    protected function readSessionData()
    {
        $this->data = $this->connection->get($this->sessionPrefix . $this->sessionId);
        $resultCode = $this->connection->getResultCode();
        if (!in_array($resultCode, [\Memcached::RES_SUCCESS, \Memcached::RES_NOTFOUND])) {
            throw new \MemcachedException('Memcache error: ' . $this->connection->getResultMessage(), $resultCode);
        }
    }

    /**
     * Write session data
     */
    protected function writeSessionData()
    {
        $this->connection->set($this->sessionPrefix . $this->sessionId, $this->data);
        $resultCode = $this->connection->getResultCode();
        if ($resultCode !== \Memcached::RES_SUCCESS) {
            throw new \MemcachedException('Memcache error: ' . $this->connection->getResultMessage(), $resultCode);
        }
    }


}