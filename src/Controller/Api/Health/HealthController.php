<?php

/*
 * Copyright (c) Romain Cottard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace Application\Controller\Api\Health;

use Application\Controller\Common\AbstractApiController;
use Eureka\Kernel\Http\Exception\HttpServiceUnavailableException;
use Psr\Http\Message\ResponseInterface;

/**
 * Class HealthController
 *
 * @author Romain Cottard
 */
class HealthController extends AbstractApiController
{
    /**
     * @return ResponseInterface
     */
    public function liveness(): ResponseInterface
    {
        return $this->getResponseJsonSuccess('ok');
    }

    /**
     * @return ResponseInterface
     * @throws HttpServiceUnavailableException
     */
    public function readiness(): ResponseInterface
    {
        return $this->getResponseJsonSuccess('ok');
    }
}
