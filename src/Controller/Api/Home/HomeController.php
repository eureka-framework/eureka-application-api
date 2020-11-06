<?php

/*
 * Copyright (c) Romain Cottard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace Application\Controller\Api\Home;

use Application\Controller\Common\AbstractApiController;
use Psr\Http\Message\ResponseInterface;

/**
 * Class HomeController
 *
 * @author Romain Cottard
 */
class HomeController extends AbstractApiController
{
    /**
     * @return ResponseInterface
     */
    public function index(): ResponseInterface
    {
        return $this->getResponseJson(['data' => 'ok']);
    }
    /**
     * @return ResponseInterface
     */
    public function ping(): ResponseInterface
    {
        return $this->getResponseJson(['data' => 'pong']);
    }
}
