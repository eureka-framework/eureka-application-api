<?php

/*
 * Copyright (c) Romain Cottard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace Application\Service;

use Eureka\Kernel\Http\Exception\HttpBadRequestException;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Class JsonWebToken
 * Exception Code Range: 1060-1069
 *
 * @author Romain Cottard
 */
class JsonWebTokenService
{
    /** @var int EXPIRATION_DELAY 7 days */
    private const EXPIRATION_DELAY = 604800;

    /** @var Sha256 $signer */
    private Sha256 $signer;

    /** @var Key $key */
    private Key $key;

    /** @var string $secretKey */
    private string $secretKey;

    /**
     * JsonWebToken constructor.
     *
     * @param string $tokenSignatureSecretKey
     */
    public function __construct(string $tokenSignatureSecretKey = 'test')
    {
        $this->secretKey = $tokenSignatureSecretKey;
        $this->key       = new Key($this->secretKey);
        $this->signer    = new Sha256();
    }

    /**
     * @param int $userId
     * @param int $currentTimestamp
     * @param int|null $expirationDelay
     * @return Token
     */
    public function generateToken(int $userId, int $currentTimestamp, int $expirationDelay = null): Token
    {
        return (new Builder())
            ->issuedAt($currentTimestamp)
            ->withClaim('uid', $userId)
            ->expiresAt($currentTimestamp + ($expirationDelay ?? self::EXPIRATION_DELAY))
            ->getToken($this->signer, $this->key)
        ;
    }

    /**
     * @param array $claims
     * @param int $currentTimestamp
     * @param int $expirationDelay
     * @return Token
     */
    public function generateTokenForClaimAccess(
        array $claims,
        int $currentTimestamp,
        int $expirationDelay = self::EXPIRATION_DELAY
    ): Token {
        $builder = (new Builder())
            ->issuedAt($currentTimestamp)
            ->expiresAt($currentTimestamp + $expirationDelay) //~ 5 days
        ;

        foreach ($claims as $key => $value) {
            $builder = $builder->withClaim($key, $value);
        }

        return $builder->getToken($this->signer, $this->key);
    }

    /**
     * @param ServerRequestInterface $serverRequest
     * @return Token
     */
    public function getTokenFromServerRequest(ServerRequestInterface $serverRequest): Token
    {
        $headerAuth = $serverRequest->getHeaderLine('Authorization');
        $cookieAuth = $serverRequest->getCookieParams()['Authorization'] ?? '';

        if (substr($headerAuth, 0, 4) === 'JWT ') {
            return $this->parseToken(substr($headerAuth, 4));
        } elseif (substr($cookieAuth, 0, 4) === 'JWT ') {
            return $this->parseToken(substr($cookieAuth, 4));
        }

        throw new HttpBadRequestException('Invalid Authorization: Token not provided', 1060);
    }

    /**
     * @param string $tokenString
     * @return Token
     * @throws \InvalidArgumentException
     */
    public function parseToken(string $tokenString): Token
    {
        return (new Parser())->parse($tokenString);
    }

    /**
     * @param Token $token
     * @return bool
     */
    public function isValidToken(Token $token): bool
    {
        return $token->verify($this->signer, $this->secretKey);
    }
}
