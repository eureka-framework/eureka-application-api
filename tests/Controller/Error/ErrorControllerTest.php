<?php

/*
 * Copyright (c) Romain Cottard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace Application\Tests\Controller\Error;

use Application\Controller\Api\Error\ErrorController;
use Application\Tests\Helper\ControllerHelperTrait;
use Eureka\Kernel\Http\Exception\HttpBadRequestException;
use Eureka\Kernel\Http\Exception\HttpForbiddenException;
use Eureka\Kernel\Http\Exception\HttpMethodNotAllowedException;
use Eureka\Kernel\Http\Exception\HttpNotFoundException;
use Eureka\Kernel\Http\Exception\HttpServiceUnavailableException;
use Eureka\Kernel\Http\Exception\HttpUnauthorizedException;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

/**
 * Class ErrorControllerTest
 *
 * @author Romain Cottard
 */
class ErrorControllerTest extends TestCase
{
    use ControllerHelperTrait;

    /**
     * @param \Exception $exception
     * @param int $httpCode
     * @param string $httpMessage
     * @return void
     * @throws \JsonException
     *
     * @dataProvider exceptionDataProvider
     */
    public function testIGetCompleteErrorResponseWhenICallErrorController(
        \Exception $exception,
        int $httpCode,
        string $httpMessage
    ): void {
        $controller = $this->getErrorController();
        $controller->setLogger(new NullLogger());

        $serverRequest = $this->getServerRequest('/');
        $response      = $controller->error($serverRequest, $exception);
        $json          = $this->getJsonObjectFromResponse($response);

        $expected = (object) [
            'errors' => [
                (object) [
                    'status' => (string) $httpCode,
                    'title'  => $httpMessage,
                    'code'   => '99',
                    'detail' => 'Error message',
                ],
            ],
            'data' => null,
        ];

        $this->assertEquals($httpCode, $response->getStatusCode());
        $this->assertEquals($expected, $json);
    }

    /**
     * @return ErrorController
     */
    private function getErrorController(): ErrorController
    {
        /** @var ErrorController $controller */
        $controller = $this->addFactoriesToController(new ErrorController());

        return $controller;
    }

    /**
     * @return array<mixed>
     */
    public function exceptionDataProvider(): array
    {
        return [
            'HttpBadRequestException'   => [
                new HttpBadRequestException('Error message', 99),
                400,
                'Bad Request',
            ],
            'HttpUnauthorizedException' => [
                new HttpUnauthorizedException('Error message', 99),
                401,
                'Unauthorized',
            ],
            'HttpForbiddenException' => [
                new HttpForbiddenException('Error message', 99),
                403,
                'Forbidden',
            ],
            'HttpNotFoundException' => [
                new HttpNotFoundException('Error message', 99),
                404,
                'Not Found',
            ],
            'HttpMethodNotAllowedException' => [
                new HttpMethodNotAllowedException('Error message', 99),
                405,
                'Method Not Allowed',
            ],
            'HttpServiceUnavailableException' => [
                new HttpServiceUnavailableException('Error message', 99),
                503,
                'Service Unavailable',
            ],
            'default exception' => [
                new \RuntimeException('Error message', 99),
                500,
                'Internal Server Error',
            ],
        ];
    }
}
