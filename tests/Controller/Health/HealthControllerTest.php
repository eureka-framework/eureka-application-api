<?php

/*
 * Copyright (c) Romain Cottard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace Application\Tests\Controller\Health;

use Application\Controller\Api\Health\HealthController;
use Application\Tests\Helper\ControllerHelperTrait;
use Eureka\Component\Database\ConnectionFactory;
use PHPUnit\Framework\TestCase;

use function Safe\json_encode;

/**
 * Class HealthControllerTest
 *
 * @author Romain Cottard
 */
class HealthControllerTest extends TestCase
{
    use ControllerHelperTrait;

    /**
     * @return void
     * @throws \Exception
     */
    public function testEndpointLivenessReturnStatusOkWhenItIsCalled(): void
    {
        $controller = $this->getHealthController();

        $response = $controller->liveness();
        $json     = $this->getJsonStringFromResponse($response);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals(json_encode(['data' => 'ok']), $json);
    }

    /**
     * @return void
     * @throws \Exception
     */
    public function testEndpointReadinessReturnStatusOkWhenItIsCalledWithOtherServicesReady(): void
    {
        $controller = $this->getHealthController();

        $response = $controller->readiness();
        $json     = $this->getJsonStringFromResponse($response);

        $this->assertEquals(json_encode(['data' => 'ok']), $json);
        $this->assertEquals(200, $response->getStatusCode());
    }

    /**
     * @return HealthController
     */
    private function getHealthController(): HealthController
    {
        $controller = new HealthController();

        /** @var HealthController $controller */
        $controller = $this->addFactoriesToController($controller);

        return $controller;
    }
}
