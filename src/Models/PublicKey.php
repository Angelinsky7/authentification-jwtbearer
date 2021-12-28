<?php

namespace Darkink\AuthentificationJwtBearer\Models;

class PublicKey
{
    public $key;
    public $signer;

    public function __construct(string $key, string $signer)
    {
        $this->key = $key;
        $this->signer = $signer;
    }
}
