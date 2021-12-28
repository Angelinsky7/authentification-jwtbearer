<?php

namespace Darkink\AuthentificationJwtBearer;

use DateTimeImmutable;
use InvalidArgumentException;
use Darkink\AuthentificationJwtBearer\Models\JwtBearerOptions;
use Darkink\AuthentificationJwtBearer\Models\PublicKey;
use Illuminate\Support\Facades\Log;
use Lcobucci\Clock\FrozenClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\IdentifiedBy;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use PhpParser\Node\Stmt\Break_;

class TokenValidator
{

    /** @var PublicKey[] */
    protected array $publicKeys;
    protected $options;

    public function __construct(array $publicKeys, JwtBearerOptions $options)
    {
        $this->publicKeys = $publicKeys;
        $this->options = $options;
    }

    public function checkToken(?string $token): UnencryptedToken | null
    {
        if ($token == null || $token == '') return false;

        foreach ($this->publicKeys as $publicKey) {
            $jwtKey = InMemory::plainText($publicKey->key);
            $configuration = Configuration::forAsymmetricSigner(
                $this->_getSigner($publicKey->signer),
                $jwtKey,
                $jwtKey
            );
            assert($configuration instanceof Configuration);
            $token = $configuration->parser()->parse($token);
            assert($token instanceof UnencryptedToken);

            $clockNow = new FrozenClock(new DateTimeImmutable(date("Y-m-d H:i:s")));

            $configuration->setValidationConstraints(
                // new IdentifiedBy(''),
                new IssuedBy($this->options->claimsIssuer ?? $this->options->authority),
                new PermittedFor($this->options->audience),
                new SignedWith($configuration->signer(), $configuration->signingKey()),
                new StrictValidAt($clockNow),
                // new LooseValidAt()
            );
            $constraints = $configuration->validationConstraints();

            // //NOTE(demarco): Only for test ?
            // try {
            //     $configuration->validator()->assert($token, ...$constraints);
            // } catch (RequiredConstraintsViolated $e) {
            //     // list of constraints violation exceptions:
            //     var_dump($e->violations());
            // }

            if ($configuration->validator()->validate($token, ...$constraints)) {
                Log::debug('TokenValidator - Validation Successed');
                return $token;
            }
        }

        Log::debug('TokenValidator - checkToken - Validation Failed');

        return null;
    }

    private function _getSigner($alg): Signer
    {
        switch ($alg) {
            case 'RS256':
                return new Signer\Rsa\Sha256();
            case 'RS512':
                return new Signer\Rsa\Sha512();
        }
        throw new InvalidArgumentException("Signer unkown: {$alg}");
    }
}
