<?php

/*
 * Copyright (c) Romain Cottard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace Application\Behat\Helper;

use Application\Behat\Context\Common\ClientApplicationContext;
use Application\Service\JsonWebTokenService;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Token;
use PHPUnit\Framework\Assert;
use Psr\Container\ContainerExceptionInterface;
use Psr\Container\NotFoundExceptionInterface;

/**
 * Trait JsonWebTokenServiceAwareTrait
 *
 * @author Romain Cottard
 */
trait JsonWebTokenServiceAwareTrait
{
    /** @var JsonWebTokenService $jwtService */
    private JsonWebTokenService $jwtService;

    /**
     * @BeforeScenario
     *
     * @return void
     * @throws ContainerExceptionInterface
     * @throws NotFoundExceptionInterface
     */
    public function initializeJsonWebTokenService(): void
    {
        $this->jwtService = ClientApplicationContext::getContainer()->get('Application\Service\JsonWebTokenService');
    }

    /**
     * @param string $tokenState
     * @param int $userId
     * @return Token
     * @throws ContainerExceptionInterface
     * @throws NotFoundExceptionInterface
     * @throws \Exception
     */
    protected function getTokenWithState(string $tokenState, int $userId): Token
    {
        return match ($tokenState) {
            'invalid' => $this->createInvalidToken($userId),
            'expired' => $this->createToken($userId, time() - 86400, 3600),
            default => $this->createToken($userId),
        };
    }

    /**
     * @param int $userId
     * @param int|null $timestamp
     * @param int|null $delay
     * @return Token
     * @throws \Exception
     */
    protected function createToken(int $userId, ?int $timestamp = null, int $delay = 604800): Token
    {
        return $this->jwtService->generateToken($userId, $timestamp ?? time(), $delay);
    }

    /**
     * @param int $userId
     * @param int|null $timestamp
     * @param int|null $delay
     * @return Token
     * @throws ContainerExceptionInterface
     * @throws NotFoundExceptionInterface
     * @throws \Exception
     */
    protected function createInvalidToken(int $userId, ?int $timestamp = null, int $delay = 604800): Token
    {
        $configuration = ClientApplicationContext::getContainer()->get('app.auth.jwt.configuration.invalid_key');
        return (new JsonWebTokenService($configuration))
            ->generateToken($userId, $timestamp ?? time(), $delay)
        ;
    }

    /**
     * @param string $tokenString
     * @return Token
     */
    protected function getTokenFromString(string $tokenString): Token
    {
        return $this->jwtService->parseToken($tokenString);
    }

    /**
     * @param string|Token $token
     * @return void
     */
    protected function assertTokenIsValid(Token|string $token): void
    {
        if (!$token instanceof Token) {
            $token = $this->getTokenFromString($token);
        }

        Assert::assertTrue($this->jwtService->isValidToken($token));
    }

    /**
     * @param string|Token $token
     * @return void
     */
    protected function assertTokenIsNotExpired(Token|string $token): void
    {
        if (!$token instanceof Token) {
            $token = $this->getTokenFromString($token);
        }

        Assert::assertFalse($token->isExpired(SystemClock::fromUTC()->now()));
    }
}
