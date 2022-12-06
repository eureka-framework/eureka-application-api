<?php

/*
 * Copyright (c) Romain Cottard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace Application\Middleware;

use Application\Domain\User\Entity\User;
use Application\Domain\User\Repository\UserRepositoryInterface;
use Application\Service\JsonWebTokenService;
use Eureka\Kernel\Http\Exception\HttpBadRequestException;
use Eureka\Kernel\Http\Exception\HttpForbiddenException;
use Eureka\Kernel\Http\Exception\HttpUnauthorizedException;
use Eureka\Component\Orm\Exception\EntityNotExistsException;
use Eureka\Component\Orm\Exception\OrmException;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Safe\Exceptions\JsonException;

/**
 * Class AuthenticationMiddleware
 * Exception Code Range: 1050-1060
 *
 * @author Romain Cottard
 */
class AuthenticationMiddleware implements MiddlewareInterface
{
    public function __construct(
        private readonly JsonWebTokenService $jsonWebTokenService,
        private readonly UserRepositoryInterface $userRepository,
        private readonly ClockInterface $clock
    ) {
    }

    /**
     * @param ServerRequestInterface $serverRequest
     * @param RequestHandlerInterface $handler
     * @return ResponseInterface
     * @throws HttpBadRequestException
     * @throws HttpUnauthorizedException
     * @throws OrmException
     * @throws JsonException
     * @throws \Exception
     */
    public function process(ServerRequestInterface $serverRequest, RequestHandlerInterface $handler): ResponseInterface
    {
        //~ Get authentication required flag from request (set in RouterMiddleware, defined in routing)
        $authenticationRequired = $serverRequest->getAttribute('authenticationRequired', false);

        //~ If auth is required, verify if auth is valid (token is valid & token not expired)
        if ($authenticationRequired) {
            $token = $this->getToken($serverRequest);
            $user  = $this->getUser($token);

            $this->assertAuthenticationIsValid($token, $user);

            //~ Register first / last access
            $this->registerDateAccess($user);

            //~ If auth is valid, set User entity in request for future usage and avoid queries on database.
            $serverRequest = $serverRequest->withAttribute('user', $user);
        }

        //~ When all is fine, handle next middleware & return response
        return $handler->handle($serverRequest);
    }

    /**
     * @param Token $token
     * @param User $user
     * @return void
     * @throws OrmException
     * @throws JsonException
     * @throws \Exception
     */
    private function assertAuthenticationIsValid(Token $token, User $user): void
    {
        if ($token->isExpired($this->clock->now())) {
            //~ Unregister token when expired, before returning exception
            $user->unregisterToken($token);
            $this->userRepository->persist($user);
            throw new HttpUnauthorizedException('Token is expired', 1050);
        }

        if (!$this->jsonWebTokenService->isValidToken($token)) {
            throw new HttpBadRequestException('Token is not valid', 1051);
        }

        if (!$user->isEnabled()) {
            throw new HttpForbiddenException('Account is disabled', 1052);
        }

        if (!$user->hasRegisteredToken($token)) {
            throw new HttpUnauthorizedException('Unknown or Revoked token', 1053);
        }
    }

    /**
     * Retrieve user from database based on user id in token.
     *
     * @param UnencryptedToken $token
     * @return User
     * @throws HttpUnauthorizedException
     */
    private function getUser(UnencryptedToken $token): User
    {
        /** @var int|string $userId */
        $userId = $token->claims()->get('uid', 0);

        try {
            /** @var User $user */
            $user = $this->userRepository->findById((int) $userId);
        } catch (EntityNotExistsException) {
            throw new HttpUnauthorizedException('User not found', 1054);
        }

        return $user;
    }

    /**
     * Extract token from request headers
     *
     * @param ServerRequestInterface $serverRequest
     * @return UnencryptedToken
     */
    private function getToken(ServerRequestInterface $serverRequest): UnencryptedToken
    {
        return $this->jsonWebTokenService->getTokenFromServerRequest($serverRequest);
    }

    /**
     * @param User $user
     * @return void
     * @throws OrmException
     * @throws \Exception
     */
    private function registerDateAccess(User $user): void
    {
        $now = $this->clock->now()->format('Y-m-d H:i:s');

        if (empty($user->getDateFirstAccess())) {
            $user->setDateFirstAccess($now);
        }

        $user->setDateLastAccess($now);
        $this->userRepository->persist($user);
    }
}
