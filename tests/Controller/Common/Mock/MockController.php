<?php

/*
 * Copyright (c) Romain Cottard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace Application\Tests\Controller\Common\Mock;

use Application\Controller\Common\AbstractApiController;
use Application\Entity\User;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Class MockController
 *
 * @author Romain Cottard
 */
class MockController extends AbstractApiController
{
    /**
     * @return ResponseInterface
     */
    public function responseJsonAction(): ResponseInterface
    {
        return $this->getResponseJson('ok');
    }

    /**
     * @return ResponseInterface
     */
    public function responseJsonSuccessAction(): ResponseInterface
    {
        return $this->getResponseJsonSuccess('ok', null, ['error']);
    }

    /**
     * @return ResponseInterface
     */
    public function responseJsonErrorAction(): ResponseInterface
    {
        return $this->getResponseJsonError(500, ['error']);
    }
}
