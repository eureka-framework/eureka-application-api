<?php

/*
 * Copyright (c) Romain Cottard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace Application\Behat\Helper;

use Application\Behat\Context\Common\ClientApplicationContext;
use PHPUnit\Framework\MockObject\Generator;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub\ConsecutiveCalls;
use Symfony\Component\DependencyInjection\Exception\InvalidArgumentException;

/**
 * Trait ServiceMockAwareTrait
 *
 * @author Romain Cottard
 */
trait ServiceMockAwareTrait
{
    /**
     * @param string $class
     * @param bool $enableOriginalConstructor
     * @return MockObject
     */
    protected function getMock(string $class, bool $enableOriginalConstructor = false): MockObject
    {
        return (new Generator())->getMock($class, [], [], '', $enableOriginalConstructor);
    }

    /**
     * @param MockObject $mock
     * @param string $method
     * @param $return
     * @param bool $useConsecutiveCall
     * @return MockObject
     */
    protected function mockMethod(
        MockObject $mock,
        string $method,
        $return,
        bool $useConsecutiveCall = false
    ): MockObject {
        if ($return instanceof \Throwable) {
            $mock->method($method)->willThrowException($return);
        } elseif ($useConsecutiveCall) {
            $mock->method($method)->will(new ConsecutiveCalls($return));
        } else {
            $mock->method($method)->willReturn($return);
        }

        return $mock;
    }

    /**
     * @param string|array $class Class name or [alias => class]
     * @param string $method
     * @param mixed $return
     * @param bool $useConsecutiveCall
     * @return void
     */
    protected function registerMockService(
        $class,
        string $method,
        $return,
        bool $useConsecutiveCall = false
    ): void {

        $serviceId = $class;

        //~ when class is an array [alias => class], override values
        if (is_array($class)) {
            $serviceId = key($class);
            $class     = current($class);
        }

        $container = ClientApplicationContext::getContainer();

        try {
            //~ Create mock & register it
            $mock = $this->getMock($class);
            $mock = $this->mockMethod($mock, $method, $return, $useConsecutiveCall);
            $container->set($serviceId, $mock);
        } catch (InvalidArgumentException $exception) {
            $mock = $container->get($serviceId);
            $this->mockMethod($mock, $method, $return, $useConsecutiveCall); // update mock will update the service in container
        }
    }
}
