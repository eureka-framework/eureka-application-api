<?php

/*
 * Copyright (c) Romain Cottard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace Application\Service;

use Application\Domain\User\Repository\UserRepositoryInterface;
use Eureka\Component\Password\PasswordChecker;
use Eureka\Kernel\Http\Exception\HttpBadRequestException;
use Eureka\Kernel\Http\Exception\HttpForbiddenException;
use Eureka\Kernel\Http\Exception\HttpUnauthorizedException;
use Eureka\Component\Orm\Exception\EntityNotExistsException;
use Eureka\Component\Orm\Exception\InvalidQueryException;
use Eureka\Component\Orm\Exception\OrmException;
use Lcobucci\JWT\Token;
use Psr\Http\Message\ServerRequestInterface;
use Safe\Exceptions\JsonException;

/**
 * Class LoginService
 *
 * @author Romain Cottard
 */
class LoginService
{
    /** @var UserRepositoryInterface $userRepository */
    private UserRepositoryInterface $userRepository;

    /** @var JsonWebTokenService $jsonWebTokenService */
    private JsonWebTokenService $jsonWebTokenService;

    /** @var PasswordChecker $passwordChecker */
    private PasswordChecker $passwordChecker;

    /**
     * LoginService constructor.
     *
     * @param JsonWebTokenService $jsonWebTokenService
     * @param UserRepositoryInterface $userRepository
     * @param PasswordChecker $passwordChecker
     */
    public function __construct(
        JsonWebTokenService $jsonWebTokenService,
        UserRepositoryInterface $userRepository,
        PasswordChecker $passwordChecker
    ) {
        $this->jsonWebTokenService = $jsonWebTokenService;
        $this->userRepository      = $userRepository;
        $this->passwordChecker     = $passwordChecker;
    }

    /**
     * @param ServerRequestInterface $serverRequest
     * @return Token
     * @throws InvalidQueryException
     * @throws OrmException
     * @throws JsonException
     */
    public function login(ServerRequestInterface $serverRequest): Token
    {
        $body = $serverRequest->getParsedBody();

        $email    = isset($body['email']) ? trim($body['email']) : '';
        $password = isset($body['password']) ? trim($body['password']) : '';

        if (empty($email) || !is_string($email)) {
            throw new HttpBadRequestException('Error with email (empty or not well formatted value)', 1200);
        }

        if (empty($password) || !is_string($password)) {
            throw new HttpBadRequestException('Error with password (empty or not well formatted value)', 1201);
        }

        try {
            //~ Retrieve user
            $user = $this->userRepository->findByEmail($email);
        } catch (EntityNotExistsException $exception) {
            throw new HttpUnauthorizedException('Invalid email or password', 1202);
        }

        if (!$user->isEnabled()) {
            throw new HttpForbiddenException('Account disabled', 1203);
        }

        //~ Verify password
        if (!$this->passwordChecker->verify($password, $user->getPassword())) {
            throw new HttpUnauthorizedException('Invalid email or password', 1202); // Same code to limit hack info
        }

        $token = $this->jsonWebTokenService->generateToken($user->getId(), time());

        //~ Register token for this user
        $user->registerToken($token);
        $this->userRepository->persist($user);

        return $token;
    }

    /**
     * @param ServerRequestInterface $serverRequest
     * @return void
     * @throws JsonException
     * @throws OrmException
     */
    public function logout(ServerRequestInterface $serverRequest): void
    {
        $token = $this->jsonWebTokenService->getTokenFromServerRequest($serverRequest);

        $userId = (int) $token->getClaim('uid');
        $user = $this->userRepository->findById($userId);

        $user->revokeToken($token);
        $this->userRepository->persist($user);
    }
}
