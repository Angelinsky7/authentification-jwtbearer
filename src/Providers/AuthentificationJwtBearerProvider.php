<?php

namespace Darkink\AuthentificationJwtBearer\Providers;

use Darkink\AuthentificationJwtBearer\AuthentificationJwtBearer;
use Darkink\AuthentificationJwtBearer\ConfigurationManager;
use Darkink\AuthentificationJwtBearer\Guards\JwtBearerGuard;
use Illuminate\Auth\RequestGuard;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\ServiceProvider;

class AuthentificationJwtBearerProvider extends ServiceProvider
{

    /**
     * Register any application services.
     *
     * @return void
     */
    public function register()
    {
        $this->registerManager();
        $this->registerGuard();
    }

    /**
     * Bootstrap any application services.
     *
     * @return void
     */
    public function boot()
    {
        //
    }

    protected function registerManager()
    {
        $this->app->singleton(ConfigurationManager::class);
    }

    protected function registerGuard()
    {
        Auth::resolved(function ($auth) {
            /** @var Illuminate\\Auth\\AuthManager $auth */

            $auth->provider('jwtbearer', function ($app, array $config) {
                return $this->makeProvider($config);
            });

            $auth->extend('jwtbearer', function ($app, $name, array $config) {
                return tap($this->makeGuard($config), function ($guard) {
                    app()->refresh('request', $guard, 'setRequest');
                });
            });
        });
    }

    protected function makeProvider(array $config)
    {
        return new JwtBearerUserProvider($config['model']);
    }


    protected function makeGuard(array $config)
    {
        return new RequestGuard(function ($request) use ($config) {
            return (new JwtBearerGuard(
                Auth::createUserProvider($config['provider']),
                new ConfigurationManager(AuthentificationJwtBearer::$options)
            ))->user($request);
        }, $this->app['request']);
    }
}
