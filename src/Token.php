<?php

class Token
{
    private $payload;
    private $header;
    private $claims;
    private $signature;

    public function parse($jwt)
    {
        $data = $this->splitJwt($jwt);
        $this->header = $this->parseHeader($data[0]);
        $this->claims = $this->parseClaims($data[1]);
        $this->signature = $this->parseSignature($this->header, $data[2]);

        foreach ($this->claims as $name => $value) {
            if (isset($this->header[$name])) {
                $this->header[$name] = $value;
            }
        }

        if ($this->signature === null) {
            unset($data[2]);
        }

        $this->payload = $data;
    }

    public function hasClaim($name)
    {
        return array_key_exists($name, $this->claims);
    }

    public function getClaim($name, $default = null)
    {
        if ($this->hasClaim($name)) {
            return $this->claims[$name];
        }

        if ($default === null) {
            throw new OutOfBoundsException('Requested claim is not configured');
        }

        return $default;
    }

    public function getClaims()
    {
        return $this->claims;
    }

    public function verify($key)
    {
        return $this->isValid($key) && !$this->isExpired();
    }

    public function isValid($key)
    {
        if (!is_string($this->signature)) {
            return false;
        }

        return hash_equals($this->signature, $this->createHash($this->getPayload(), $key));
    }

    public function isExpired()
    {
        if (!$this->hasClaim('exp')) return false;

        $expTime = $this->getClaim('exp', time());
        return time() > $expTime - (1 * 60);
    }

    private function splitJwt($jwt)
    {
        if (!is_string($jwt)) {
            throw new InvalidArgumentException('The JWT string must have two dots');
        }

        $data = explode('.', $jwt);

        if (count($data) != 3) {
            throw new InvalidArgumentException('The JWT string must have two dots');
        }

        return $data;
    }

    private function parseHeader($data)
    {
        $header = (array)$this->jsonDecode($this->base64UrlDecode($data));

        if (isset($header['enc'])) {
            throw new InvalidArgumentException('Encryption is not supported yet');
        }

        return $header;
    }

    private function parseClaims($data)
    {
        return (array)$this->jsonDecode($this->base64UrlDecode($data));
    }

    private function parseSignature(array $header, $data)
    {
        if ($data == '' || !isset($header['alg']) || $header['alg'] == 'none') {
            return null;
        }

        $hash = $this->base64UrlDecode($data);

        return $hash;
    }

    private function base64UrlDecode($data)
    {
        if ($remainder = strlen($data) % 4) {
            $data .= str_repeat('=', 4 - $remainder);
        }

        return base64_decode(strtr($data, '-_', '+/'));
    }

    private function jsonDecode($json)
    {
        $data = json_decode($json);

        if (version_compare(PHP_VERSION, '5.3.0', '>=')) {
            if (json_last_error() != JSON_ERROR_NONE) {
                throw new RuntimeException('Error while decoding to JSON: ' . json_last_error_msg());
            }
        } else if ($data == null) {
            throw new RuntimeException('Error while decoding to JSON');
        }

        return $data;
    }

    private function createHash($payload, $key)
    {
        return hash_hmac('sha256', $payload, $key, true);
    }

    private function getPayload()
    {
        return $this->payload[0] . '.' . $this->payload[1];
    }

}