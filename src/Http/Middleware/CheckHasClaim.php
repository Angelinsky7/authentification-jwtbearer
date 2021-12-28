<?php

namespace Darkink\AuthentificationJwtBearer\Http\Middleware;

use Closure;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\Request;

class CheckHasClaim
{
    public function handle(Request $request, Closure $next, string $claim)
    {
        $claims = explode($this->getSeparator(), $claim);
        if (!$request->user()->hasClaim(...$claims)) {
            $this->unauthenticated($request);
        }

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

    protected function getSeparator()
    {
        return '|';
    }
}
