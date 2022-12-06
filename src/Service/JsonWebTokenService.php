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
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Class JsonWebToken
 * Exception Code Range: 1060-1069
 *
 * @author Romain Cottard
 */
class JsonWebTokenService
{
    public const EXPIRATION_DELAY = 604800; // 7 days

    public function __construct(public readonly Configuration $configuration)
    {
    }

    /**
     * @param int $userId
     * @param int $currentTimestamp
     * @param int $expirationDelay
     * @return Token
     * @throws \Exception
     */
    public function generateToken(
        int $userId,
        int $currentTimestamp,
        int $expirationDelay = self::EXPIRATION_DELAY
    ): Token {
        $dateIssue      = (new \DateTimeImmutable())->setTimestamp($currentTimestamp);
        $dateExpiration = (new \DateTimeImmutable())->setTimestamp($currentTimestamp + $expirationDelay);

        return $this->configuration->builder()
            ->issuedAt($dateIssue)
            ->withClaim('uid', $userId)
            ->expiresAt($dateExpiration)
            ->getToken($this->configuration->signer(), $this->configuration->signingKey())
        ;
    }

    /**
     * @param ServerRequestInterface $serverRequest
     * @return UnencryptedToken
     */
    public function getTokenFromServerRequest(ServerRequestInterface $serverRequest): UnencryptedToken
    {
        $headerAuth = $serverRequest->getHeaderLine('Authorization');
        $cookieAuth = $serverRequest->getCookieParams()['Authorization'] ?? '';

        if (str_starts_with($headerAuth, 'JWT ')) {
            return $this->parseToken(substr($headerAuth, 4));
        } elseif (str_starts_with($cookieAuth, 'JWT ')) {
            return $this->parseToken(substr($cookieAuth, 4));
        }

        throw new HttpBadRequestException('Invalid Authorization: Token not provided', 1060);
    }

    /**
     * @param string $tokenString
     * @return UnencryptedToken
     * @throws \InvalidArgumentException
     */
    public function parseToken(string $tokenString): UnencryptedToken
    {
        /** @var UnencryptedToken $token */
        $token = $this->configuration->parser()->parse($tokenString);

        return $token;
    }

    /**
     * @param Token $token
     * @return bool
     */
    public function isValidToken(Token $token): bool
    {
        try {
            $constraints = $this->configuration->validationConstraints();

            $this->configuration->validator()
                ->assert($token, ...$constraints)
            ;

            return true;
        } catch (RequiredConstraintsViolated) {
            return false;
        }
    }
}
