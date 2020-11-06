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
use Lcobucci\JWT\Token;
use PHPUnit\Framework\Assert;

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
     */
    public function initializeJsonWebTokenService(): void
    {
        $this->jwtService = ClientApplicationContext::getContainer()->get('Application\Service\JsonWebTokenService');
    }

    /**
     * @param string $tokenState
     * @param int $userId
     * @return Token
     */
    protected function getTokenWithState(string $tokenState, int $userId): Token
    {
        switch ($tokenState) {
            case 'invalid':
                $token = $this->createInvalidToken($userId);
                break;
            case 'expired':
                $token = $this->createToken($userId, time() - 86400, 3600);
                break;
            case 'valid':
            default:
                $token = $this->createToken($userId);
                break;
        }

        return $token;
    }

    /**
     * @param int $userId
     * @param int|null $timestamp
     * @param int|null $delay
     * @return Token
     */
    protected function createToken(int $userId, ?int $timestamp = null, ?int $delay = null): Token
    {
        return $this->jwtService->generateToken($userId, $timestamp ?? time(), $delay);
    }

    /**
     * @param int $userId
     * @param int|null $timestamp
     * @param int|null $delay
     * @return Token
     */
    protected function createInvalidToken(int $userId, ?int $timestamp = null, ?int $delay = null): Token
    {
        return (new JsonWebTokenService('invalid_secret_key'))
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
    protected function assertTokenIsValid($token): void
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
    protected function assertTokenIsNotExpired($token): void
    {
        if (!$token instanceof Token) {
            $token = $this->getTokenFromString($token);
        }

        Assert::assertFalse($token->isExpired());
    }
}
