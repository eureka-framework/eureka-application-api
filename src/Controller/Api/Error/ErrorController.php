<?php

/*
 * Copyright (c) Romain Cottard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace Application\Controller\Api\Error;

use Application\Controller\Common\AbstractApiController;
use Eureka\Kernel\Http\Controller\ErrorControllerInterface;
use Eureka\Kernel\Http\Exception;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Class ErrorController
 *
 * @author Romain Cottard
 */
class ErrorController extends AbstractApiController implements ErrorControllerInterface
{
    /**
     * @param ServerRequestInterface $serverRequest
     * @param \Exception $exception
     * @return ResponseInterface
     * @throws
     */
    public function error(ServerRequestInterface $serverRequest, \Exception $exception): ResponseInterface
    {
        switch (true) {
            case $exception instanceof Exception\HttpBadRequestException:
                $httpCode = 400;
                break;
            case $exception instanceof Exception\HttpUnauthorizedException:
                $httpCode = 401;
                break;
            case $exception instanceof Exception\HttpForbiddenException:
                $httpCode = 403;
                break;
            case $exception instanceof Exception\HttpNotFoundException:
                $httpCode = 404;
                break;
            case $exception instanceof Exception\HttpMethodNotAllowedException:
                $httpCode = 405;
                break;
            case $exception instanceof Exception\HttpConflictException:
                $httpCode = 409;
                break;
            case $exception instanceof Exception\HttpTooManyRequestsException:
                $httpCode = 429;
                break;
            case $exception instanceof Exception\HttpServiceUnavailableException:
                $httpCode = 503;
                break;
            default:
                $httpCode = 500;
        }

        return $this->getResponseJsonError($httpCode, [$this->getErrorItem($httpCode, $exception)]);
    }
}
