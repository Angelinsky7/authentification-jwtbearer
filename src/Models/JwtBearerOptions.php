<?php

namespace Darkink\AuthentificationJwtBearer\Models;

use DateInterval;
use Illuminate\Support\Facades\Date;

class JwtBearerOptions {
    public bool $requireHttpsMetadata = true; //TODO(demarco): Need implementation
    public string $metadataAddress = '.well-known/openid-configuration';
    public ?string $authority;
    public ?string $audience;
    public ?string $claimsIssuer = null;

    //TODO(demarco): Need implementation
    public DateInterval $automaticRefreshInterval;
    public DateInterval $refreshInterval;
    public bool $saveToken = true;
    public bool $includeErrorDetails = true;
    public bool $refreshOnIssuerKeyNotFound = true;

    //?TokenValidationParameters
    //?SecurityTokenValidators

    public function __construct()
    {
        $this->automaticRefreshInterval = new DateInterval('P1D');
        $this->refreshInterval = new DateInterval('PT30S');
    }
}
