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
use Eureka\Component\Orm\EntityInterface;
use Eureka\Kernel\Http\Exception\HttpBadRequestException;
use Eureka\Kernel\Http\Exception\HttpForbiddenException;
use Eureka\Kernel\Http\Exception\HttpUnauthorizedException;
use Eureka\Component\Orm\Exception\EntityNotExistsException;
use Eureka\Component\Orm\Exception\OrmException;
use Lcobucci\JWT\Token;
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
    /** @var JsonWebTokenService $jsonWebTokenService */
    private JsonWebTokenService $jsonWebTokenService;

    /** @var UserRepositoryInterface $userRepository */
    private UserRepositoryInterface $userRepository;

    /** @var \DateTimeImmutable $dateNow */
    private \DateTimeImmutable $dateNow;

    /**
     * AuthenticationMiddleware constructor.
     *
     * @param JsonWebTokenService $jsonWebTokenService
     * @param UserRepositoryInterface $userRepository
     * @param \DateTimeImmutable $dateNow
     */
    public function __construct(
        JsonWebTokenService $jsonWebTokenService,
        UserRepositoryInterface $userRepository,
        \DateTimeImmutable $dateNow
    ) {
        $this->jsonWebTokenService = $jsonWebTokenService;
        $this->userRepository      = $userRepository;
        $this->dateNow             = $dateNow;
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
     */
    private function assertAuthenticationIsValid(Token $token, User $user): void
    {
        if ($token->isExpired()) {
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
     * @param Token $token
     * @return User|EntityInterface
     * @throws HttpUnauthorizedException
     */
    private function getUser(Token $token): User
    {
        $userId = (int) $token->getClaim('uid');

        try {
            $user = $this->userRepository->findById($userId);
        } catch (EntityNotExistsException $exception) {
            throw new HttpUnauthorizedException('User not found', 1054);
        }

        return $user;
    }

    /**
     * Extract token from request headers
     *
     * @param ServerRequestInterface $serverRequest
     * @return Token
     */
    private function getToken(ServerRequestInterface $serverRequest): Token
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
        $now = $this->dateNow->format('Y-m-d H:i:s');

        if (empty($user->getDateFirstAccess())) {
            $user->setDateFirstAccess($now);
        }

        $user->setDateLastAccess($now);
        $this->userRepository->persist($user);
    }
}
