<?php

namespace Darkink\AuthentificationJwtBearer\Providers;

use RuntimeException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Support\Facades\Log;

class JwtBearerUserProvider implements UserProvider
{
    protected string $model;

    public function __construct(string $model)
    {
        $this->model = $model;
    }

    public function retrieveById($identifier)
    {
        $user = $this->createModel();
        $user->id = $identifier['sub'];

        $this->setCustomProperties($user, $identifier);

        return $user;
    }

    protected function setCustomProperties($user, $claims)
    {
        $this->setPropertyToUserIfExist($user, 'name', 'name', $claims);
        $this->setPropertyToUserIfExist($user, 'email', 'email', $claims);
        $this->setPropertyToUserIfExist($user, 'claims', 'scopes', $claims);
        $this->setPropertyToUserIfExist($user, 'roles', 'roles', $claims);
    }

    protected function setPropertyToUserIfExist($user, $property, $claim, $claims)
    {
        if (array_key_exists($claim, $claims)) {
            $user[$property] = $claims[$claim];
        }
    }

    public function createModel()
    {
        $class = '\\' . ltrim($this->model, '\\');

        return new $class;
    }

    public function retrieveByToken($identifier, $token)
    {
        throw new RuntimeException('retrieveByToken function is not available.');
    }

    public function updateRememberToken(Authenticatable $user, $token)
    {
        throw new RuntimeException('updateRememberToken function is not available.');
    }

    public function retrieveByCredentials(array $credentials)
    {
        throw new RuntimeException('retrieveByCredentials function is not available.');
    }

    public function validateCredentials(Authenticatable $user, array $credentials)
    {
        throw new RuntimeException('validateCredentials function is not available.');
    }

    public function getProviderName()
    {
        return 'jwtbearer';
    }
}
