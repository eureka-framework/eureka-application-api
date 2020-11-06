<?php

/*
 * Copyright (c) Romain Cottard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace Application\Controller\Common;

use Eureka\Kernel\Http\Controller\Controller;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Class HomeController
 *
 * @author Romain Cottard
 */
abstract class AbstractApiController extends Controller
{
    /**
     * @param ServerRequestInterface|null $request
     * @return void
     */
    public function preAction(?ServerRequestInterface $request = null): void
    {
        parent::preAction($request);

        $this->setServerRequest($request);
    }

    /**
     * @param mixed $data
     * @param array|null $meta
     * @param array|null $errors
     * @return ResponseInterface
     */
    protected function getResponseJsonSuccess(
        $data,
        ?array $meta = null,
        ?array $errors = null
    ): ResponseInterface {
        $content = [
            'data' => $data
        ];

        if (!empty($meta)) {
            $content['meta'] = $meta;
        }

        if ($errors !== null && empty($errors)) {
            $content['errors'] = $errors;
        }

        return $this->getResponseJson($content, 200, true);
    }

    /**
     * @param int $httpCode
     * @param array $errors
     * @param array|null $meta
     * @param mixed $data
     * @return ResponseInterface
     */
    protected function getResponseJsonError(
        int $httpCode,
        array $errors,
        ?array $meta = null,
        $data = null
    ): ResponseInterface {
        $content = [
            'errors' => $errors
        ];

        if (!empty($meta)) {
            $content['meta'] = $meta;
        }

        //~ Can add "payload" data to the error response
        if (!empty($data)) {
            $content['data'] = $data;
        }

        return $this->getResponseJson($content, $httpCode, true);
    }

    /**
     * @param int $code
     * @param \Exception $exception
     * @return array
     * @codeCoverageIgnore
     */
    protected function getErrorItem(int $code, \Exception $exception)
    {
        //~ Ajax response error - JsonApi.org error object format + trace
        $error = [
            'status' => (string) $code,
            'title'  => self::HTTP_CODE_MESSAGES[$code] ?? 'Unknown',
            'code'   => !empty($exception->getCode()) ? (string) $exception->getCode() : '99',
            'detail' => !empty($exception->getMessage()) ? $exception->getMessage() : 'Undefined message',
        ];

        if ($this->isDebug()) {
            $error['trace'] = $exception->getTraceAsString();
        }

        return $error;
    }
}
