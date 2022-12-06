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
     */
    public function error(ServerRequestInterface $serverRequest, \Exception $exception): ResponseInterface
    {
        $httpCode = match (true) {
            $exception instanceof Exception\HttpBadRequestException => 400,
            $exception instanceof Exception\HttpUnauthorizedException => 401,
            $exception instanceof Exception\HttpForbiddenException => 403,
            $exception instanceof Exception\HttpNotFoundException => 404,
            $exception instanceof Exception\HttpMethodNotAllowedException => 405,
            $exception instanceof Exception\HttpConflictException => 409,
            $exception instanceof Exception\HttpTooManyRequestsException => 429,
            $exception instanceof Exception\HttpServiceUnavailableException => 503,
            default => 500,
        };

        return $this->getResponseJsonError($httpCode, [$this->getErrorItem($httpCode, $exception)]);
    }
}
