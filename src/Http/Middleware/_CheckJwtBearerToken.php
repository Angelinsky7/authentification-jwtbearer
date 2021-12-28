<?php

namespace Darkink\AuthentificationJwtBearer\Http\Middleware;

use Closure;
use Darkink\AuthentificationJwtBearer\AuthentificationJwtBearer;
use Darkink\AuthentificationJwtBearer\ConfigurationManager;
use Darkink\AuthentificationJwtBearer\Guards\JwtBearerGuard;
use Darkink\AuthentificationJwtBearer\SecurityKeyManager;
use Darkink\AuthentificationJwtBearer\TokenValidator;
use App\Models\User;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;

use function Psy\debug;

class CheckJwtBearerToken
{
    public function handle(Request $request, Closure $next, $role = null)
    {
        $user = Auth::user();

        //TODO(demarco): It's not working....

        if (!$user) {
            $this->unauthenticated($request);
        }

        return $next($request);

        // Log::debug('CheckJwtBearerToken - Start');
        // //TODO(demarco): what can we put in cache ????
        // $configurationManager = new ConfigurationManager(AuthentificationJwtBearer::$options);
        // $jwks = $configurationManager->getConfiguration();

        // $keyManager = new SecurityKeyManager($configurationManager->getOptions(), $jwks);
        // $keys = $keyManager->buildKeys();

        // $validator = new TokenValidator($keys, $configurationManager->getOptions());
        // $token = $request->bearerToken();
        // if (!$validator->checkToken($token)) {
        //     $this->unauthenticated($request);
        // }

        // // $user = $this->getUserFromToken($token);
        // // Auth::login($user);

        // Log::debug('CheckJwtBearerToken - End');

        return $next($request);
    }

    protected function unauthenticated($request)
    {
        throw new AuthenticationException('Unauthenticated.', [], $this->redirectTo($request));
    }

    protected function redirectTo($request)
    {
        //
    }
}
