<?php

/*
 * Copyright (c) Romain Cottard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace Application\Tests\Helper;

use Eureka\Kernel\Http\Controller\Controller;
use Nyholm\Psr7\Factory\Psr17Factory;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Trait ControllerHelperTrait
 *
 * @author Romain Cottard
 */
trait ControllerHelperTrait
{
    /**
     * @param Controller $controller
     * @return Controller
     */
    protected function addFactoriesToController(Controller $controller): Controller
    {
        $httpFactory = new Psr17Factory();

        $controller->setResponseFactory($httpFactory);
        $controller->setUriFactory($httpFactory);
        $controller->setServerRequestFactory($httpFactory);
        $controller->setRequestFactory($httpFactory);
        $controller->setStreamFactory($httpFactory);

        return $controller;
    }

    /**
     * @param string $path
     * @param string $method
     * @param array<mixed> $query
     * @param array<mixed> $body
     * @param array<mixed> $headers
     * @return ServerRequestInterface
     */
    protected function getServerRequest(
        string $path,
        string $method = 'GET',
        array $query = [],
        array $body = [],
        array $headers = []
    ): ServerRequestInterface {
        $httpFactory   = new Psr17Factory();

        $uri           = $httpFactory->createUri($path);
        $serverRequest = $httpFactory->createServerRequest($method, $uri);

        if (!empty($query)) {
            $serverRequest = $serverRequest->withQueryParams($query);
        }

        if (!empty($body)) {
            $serverRequest = $serverRequest->withParsedBody($body);
        }

        $headers['Accept']       = 'application/json';
        $headers['Content-Type'] = 'application/json';

        foreach ($headers as $name => $value) {
            $serverRequest = $serverRequest->withAddedHeader($name, $value);
        }

        return $serverRequest;
    }

    /**
     * @param ResponseInterface $response
     * @return \stdClass
     * @throws \JsonException
     */
    protected function getJsonObjectFromResponse(ResponseInterface $response): \stdClass
    {
        return (object) json_decode($this->getJsonStringFromResponse($response), flags: JSON_THROW_ON_ERROR);
    }

    /**
     * @param ResponseInterface $response
     * @return string
     */
    protected function getJsonStringFromResponse(ResponseInterface $response): string
    {
        $body = $response->getBody();
        $body->rewind();

        return $body->getContents();
    }
}
