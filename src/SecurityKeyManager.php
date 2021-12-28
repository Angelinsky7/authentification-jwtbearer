<?php

namespace Darkink\AuthentificationJwtBearer;

use InvalidArgumentException;
use Darkink\AuthentificationJwtBearer\Models\JwtBearerOptions;
use Darkink\AuthentificationJwtBearer\Models\PublicKey;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Math\BigInteger;

class SecurityKeyManager
{

    protected $options;
    protected $jwks;

    protected array $publicKeys = [];

    public function __construct(JwtBearerOptions $options, array $jwks)
    {
        if ($options == null) {
            throw new InvalidArgumentException('option cannot be null');
        }
        if ($jwks == null || !is_array($jwks) || count($jwks) == 0) {
            throw new InvalidArgumentException('jwks is not valid');
        }

        $this->options = $options;
        $this->jwks = $jwks;
    }

    public function buildKeys()
    {
        $this->publicKeys = [];

        foreach ($this->jwks['keys'] as $keyDefinition) {
            $publicKey = $this->_createPulicKey($keyDefinition);
            $keyStringFormat = "{$publicKey}";
            $ssl_publicKey = openssl_pkey_get_public($keyStringFormat);
            $publicKeyInfo = openssl_pkey_get_details($ssl_publicKey);
            $this->publicKeys[] = new PublicKey($publicKeyInfo['key'], $keyDefinition['alg']);
        }

        return $this->publicKeys;
    }

    private function _base64DecodeUrl($data)
    {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
    }

    private function _createPulicKey($keyDefinition)
    {
        $modulus  = $keyDefinition['n'];
        $exponent = $keyDefinition['e'];
        $modulus  = new BigInteger($this->_base64DecodeUrl($modulus), 256);
        $exponent = new BigInteger($this->_base64DecodeUrl($exponent), 256);
        $rsa = PublicKeyLoader::loadPublicKey([
            'n' => $modulus,
            'e' => $exponent
        ]);
        return $rsa;
    }
}
