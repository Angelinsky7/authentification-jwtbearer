<?php

namespace Darkink\AuthentificationJwtBearer;

use Darkink\AuthentificationJwtBearer\Models\JwtBearerOptions;

class AuthentificationJwtBearer
{

    public static JwtBearerOptions $options;

    public static function setOptions(JwtBearerOptions $options)
    {
        static::$options = $options;
    }

}
