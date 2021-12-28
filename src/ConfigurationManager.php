<?php

namespace Darkink\AuthentificationJwtBearer;

use DateTimeImmutable;
use InvalidArgumentException;
use Darkink\AuthentificationJwtBearer\Models\JwtBearerOptions;
use Carbon\Exceptions\InvalidFormatException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class ConfigurationManager
{

    protected JwtBearerOptions $options;

    private const CACHE_CONFIGURATION_KEY = 'AuthentificationJwtBearer.ConfigurationManager.Configuration';
    private const CACHE_SYNCAFTER_KEY = 'AuthentificationJwtBearer.ConfigurationManager.SyncAfter';
    private const CACHE_LASTREFRESH_KEY = 'AuthentificationJwtBearer.ConfigurationManager.LastRefresh';

    public function __construct(JwtBearerOptions $options)
    {
        if ($options == null) {
            throw new InvalidArgumentException('option cannot be null');
        }
        $this->options = $options;
    }

    public function getOptions()
    {
        return $this->options;
    }

    public function getConfiguration()
    {
        $now = new DateTimeImmutable();

        $configuration = Cache::get(self::CACHE_CONFIGURATION_KEY, null);
        $syncAfter = Cache::get(self::CACHE_SYNCAFTER_KEY, null);
        $lastRefresh = Cache::get(self::CACHE_LASTREFRESH_KEY, null);

        if ($configuration != null && $syncAfter > $now) {
            return $configuration;
        }

        Log::debug("ConfigurationManager - Request GET: {$this->options->authority}/{$this->options->metadataAddress}");
        //TODO(demarco): must add exception handling...
        $discoveryResponse = Http::get("{$this->options->authority}/{$this->options->metadataAddress}");
        $discoveryResponse->throw();
        $discovery = $discoveryResponse->json();
        if (!array_key_exists('jwks_uri', $discovery)) {
            throw new InvalidFormatException('discovery document does not contain a jwks_uri field');
        }
        $jwks_uri = $discovery['jwks_uri'];
        Log::debug("ConfigurationManager - Request GET: {$jwks_uri}");
        $jwks_uriResponse = Http::get($jwks_uri);
        $jwks = $jwks_uriResponse->json();
        if (!array_key_exists('keys', $jwks) && count($jwks['keys']) > 0) {
            throw new InvalidFormatException('jwks document does not contain a key field with at least one element');
        }

        $configuration = $jwks;
        $lastRefresh = new DateTimeImmutable();
        $syncAfter = $lastRefresh->add($this->options->automaticRefreshInterval);

        Cache::put(self::CACHE_CONFIGURATION_KEY, $configuration);
        Cache::put(self::CACHE_SYNCAFTER_KEY, $syncAfter);
        Cache::put(self::CACHE_LASTREFRESH_KEY, $lastRefresh);

        return $configuration;
    }

    public function requestRefresh()
    {
        $now = new DateTimeImmutable();
        $lastRefresh = Cache::get(self::CACHE_LASTREFRESH_KEY, null);

        if ($now >= $lastRefresh->add($this->options->refreshInterval)) {
            $syncAfter = $now;
            Cache::put(self::CACHE_SYNCAFTER_KEY, $syncAfter);
        }
    }
}
