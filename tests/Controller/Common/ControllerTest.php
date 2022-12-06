<?php

/*
 * Copyright (c) Romain Cottard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace Application\Tests\Controller\Common;

use Application\Tests\Controller\Common\Mock\MockController;
use Application\Tests\Helper\ControllerHelperTrait;
use Application\Tests\Helper\UserHelperTrait;
use PHPUnit\Framework\TestCase;

/***
 * Class ControllerTest
 *
 * @author Romain Cottard
 */
class ControllerTest extends TestCase
{
    use ControllerHelperTrait;
    use UserHelperTrait;

    /**
     * @return void
     */
    public function testIHaveCorrectResponseWhenIUseGetResponseJson(): void
    {
        $controller = $this->getMockController();

        $response = $controller->responseJsonAction();
        $json     = $this->getJsonStringFromResponse($response);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals(json_encode('ok'), $json);
    }

    /**
     * @return void
     */
    public function testIHaveCorrectResponseWhenIUseGetResponseJsonSuccess(): void
    {
        $controller = $this->getMockController();

        $response = $controller->responseJsonSuccessAction();
        $json     = $this->getJsonStringFromResponse($response);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals(json_encode(['data' => 'ok', 'errors' => ['error']]), $json);
    }

    /**
     * @return void
     */
    public function testIHaveCorrectResponseWhenIUseGetResponseJsonError(): void
    {
        $controller = $this->getMockController();

        $response = $controller->responseJsonErrorAction();
        $json     = $this->getJsonStringFromResponse($response);

        $this->assertEquals(500, $response->getStatusCode());
        $this->assertEquals(json_encode(['data' => null, 'errors' => ['error']]), $json);
    }

    /**
     * @return MockController
     */
    private function getMockController(): MockController
    {
        /** @var MockController $controller */
        $controller = $this->addFactoriesToController(new MockController());

        return $controller;
    }
}
