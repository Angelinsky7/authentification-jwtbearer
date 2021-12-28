<?php

namespace Darkink\AuthentificationJwtBearer\Traits;

/**
 * @property string[] $claims
 */
trait HasClaimTrait
{

    public function hasClaim(string ...$claims)
    {
        foreach ($claims as $claim) {
            if (in_array($claim, $this->claims)) {
                return true;
            }
        }
        return false;
    }
}
