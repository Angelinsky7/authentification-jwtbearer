<?php

namespace Darkink\AuthentificationJwtBearer\Guards;

use Darkink\AuthentificationJwtBearer\ConfigurationManager;
use Darkink\AuthentificationJwtBearer\SecurityKeyManager;
use Darkink\AuthentificationJwtBearer\TokenValidator;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

class JwtBearerGuard
{

    protected UserProvider $provider;
    protected ?Authenticatable $user = null;
    protected ConfigurationManager $configurationManager;

    public function __construct(
        UserProvider $provider,
        ConfigurationManager $configurationManager
    ) {
        $this->provider = $provider;
        $this->configurationManager = $configurationManager;
    }

    public function user(Request $request)
    {
        if ($request->bearerToken()) {
            return $this->authenticateViaBearerToken($request);
        }
    }

    protected function authenticateViaBearerToken($request)
    {
        $jwks = $this->configurationManager->getConfiguration();
        $keyManager = new SecurityKeyManager($this->configurationManager->getOptions(), $jwks);
        $keys = $keyManager->buildKeys();

        $validator = new TokenValidator($keys, $this->configurationManager->getOptions());
        $token = $request->bearerToken();
        $validatedToken = $validator->checkToken($token);
        if (!$validatedToken) {
            return;
        }

        $claims = $validatedToken->claims()->all();
        $user = $this->provider->retrieveById($claims);

        if (!$user) {
            return;
        }

        return $user;
    }

}
