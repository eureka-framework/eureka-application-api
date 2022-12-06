<?php

/*
 * Copyright (c) Romain Cottard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace Application\Controller\Api\Authentication;

use Application\Controller\Common\AbstractApiController;
use Application\Service\JsonWebTokenService;
use Application\Service\LoginService;
use Eureka\Component\Orm\Exception\InvalidQueryException;
use Eureka\Component\Orm\Exception\OrmException;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Safe\Exceptions\JsonException;

/**
 * Class TokenController
 *
 * @author Romain Cottard
 */
class TokenController extends AbstractApiController
{
    private JsonWebTokenService $jsonWebTokenService;
    private LoginService $userLoginService;
    private ClockInterface $clock;

    /**
     * TokenController constructor.
     *
     * @param JsonWebTokenService $jsonWebTokenService
     * @param LoginService $userLoginService
     * @param ClockInterface $clock
     */
    public function __construct(
        JsonWebTokenService $jsonWebTokenService,
        LoginService $userLoginService,
        ClockInterface $clock
    ) {
        $this->jsonWebTokenService = $jsonWebTokenService;
        $this->userLoginService    = $userLoginService;
        $this->clock               = $clock;
    }

    /**
     * @param ServerRequestInterface $serverRequest
     * @return ResponseInterface
     * @throws InvalidQueryException
     * @throws OrmException
     * @throws JsonException
     */
    public function get(ServerRequestInterface $serverRequest): ResponseInterface
    {
        $token = $this->userLoginService->login($serverRequest);

        return $this->getResponseJsonSuccess(['token' => $token->toString()]);
    }

    /**
     * @param ServerRequestInterface $serverRequest
     * @return ResponseInterface
     */
    public function verify(ServerRequestInterface $serverRequest): ResponseInterface
    {
        $token = $this->jsonWebTokenService->getTokenFromServerRequest($serverRequest);

        $content = [
            'valid'   => $this->jsonWebTokenService->isValidToken($token),
            'expired' => $token->isExpired($this->clock->now()),
        ];

        return $this->getResponseJsonSuccess($content);
    }

    /**
     * @param ServerRequestInterface $serverRequest
     * @return ResponseInterface
     * @throws JsonException|OrmException
     */
    public function revoke(ServerRequestInterface $serverRequest): ResponseInterface
    {
        $this->userLoginService->logout($serverRequest);

        return $this->getResponseJsonSuccess('ok');
    }
}
