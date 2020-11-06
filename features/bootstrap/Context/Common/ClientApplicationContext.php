<?php

/*
 * Copyright (c) Romain Cottard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace Application\Behat\Context\Common;

use Behat\Behat\Context\Context;
use Eureka\Kernel\Http\Application\Application;
use Eureka\Kernel\Http\Kernel;
use DG\BypassFinals;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseInterface;
use Safe\Exceptions\JsonException;

use function Safe\json_decode;

/**
 * Class ClientApplicationContext
 *
 * @author Romain Cottard
 */
class ClientApplicationContext implements Context
{
    /** @var Kernel|null */
    private static ?Kernel $kernel;

    /** @var Application|null */
    private static ?Application $application;

    /** @var ResponseInterface|null $response */
    private static ?ResponseInterface $response;

    /** @var \stdClass|null $responseObject */
    private static ?\stdClass $responseObject;

    /**
     * Class constructor.
     *
     * @throws \Exception
     */
    public function __construct()
    {
        //~ Pre-initialize application for base container (used in many context constructors)
        $this->initialize();
    }

    /**
     * @return void
     *
     * @BeforeSuite
     */
    public static function prepare()
    {
        //~ Enable bypass final class for clients
        BypassFinals::enable();
    }

    /**
     * When a service is already instantiate in container, it could not be replaced.
     * So, the initialization must be done before each scenario to allow update of service in container.
     *
     * @BeforeScenario
     *
     * @return void
     * @throws \Exception
     */
    public function initialize(): void
    {
        //~ When kernel is already defined, reset the container before resetting the kernel to avoid memory leak
        if (isset(self::$kernel)) {
            self::getContainer()->reset();
        }

        //~ Reset vars & force reset application & kernel properties (to ensure we have no memory leak)
        self::$responseObject = null;
        self::$response       = null;
        self::$application    = null;
        self::$kernel         = null;

        //~ Always start a new kernel & application
        self::$kernel      = $this->getKernel();
        self::$application = new Application(self::$kernel);
    }

    /**
     * @When I send the request to the endpoint :arg1 with http method :arg2
     *
     * @param string $path
     * @param string $method
     * @return void
     * @throws JsonException
     */
    public function iSendTheRequestToTheEndpointWithHttpMethod(string $path, string $method): void
    {
        $serverRequest = ServerRequestContext::createServerRequest($method, $path);

        //~ Get response from app
        self::$response = self::$application->run($serverRequest);

        //~ Get content response à json object decoded
        $responseString = (string) self::$response->getBody();
        self::$responseObject = json_decode($responseString);

        //~ Rewind response body (for further usage)
        self::$response->getBody()->rewind();

    }

    /**
     * @When I send :arg1 requests to the endpoint :arg2 with http method :arg3
     *
     * @param int $number
     * @param string $path
     * @param string $method
     * @return void
     * @throws JsonException
     */
    public function iSendRequestsToTheEndpointWithHttpMethod(int $number, string $path, string $method): void
    {
        $serverRequest = ServerRequestContext::createServerRequest($method, $path);

        //~ Skip N-1 first requests
        for ($n = 1; $n < $number; $n++) {
            self::$application->run($serverRequest);
        }

        //~ Keep response from app only for the last request
        self::$response = self::$application->run($serverRequest);

        //~ Get content response as json object decoded
        $responseString = (string) self::$response->getBody();
        self::$responseObject = json_decode($responseString);

        //~ Rewind response body (for further usage)
        self::$response->getBody()->rewind();

    }

    /**
     * @return ContainerInterface
     */
    public static function getContainer(): ContainerInterface
    {
        return self::$kernel->getContainer();
    }

    /**
     * @return ResponseInterface
     */
    public static function getResponse(): ResponseInterface
    {
        return self::$response;
    }

    /**
     * @return \stdClass
     */
    public static function getResponseContentObject(): \stdClass
    {
        return self::$responseObject;
    }

    /**
     * @return Kernel
     * @throws \Exception
     */
    private static function getKernel(): Kernel
    {
        $root  = realpath(__DIR__ . '/../../../..');
        $env   = 'test';
        $debug = true;

        return new Kernel($root, $env, $debug);
    }
}
