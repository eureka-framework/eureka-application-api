<?php

/*
 * Copyright (c) Romain Cottard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace Application\Tests\Controller\Authentication;

use Application\Controller\Api\Authentication\TokenController;
use Application\Service\JsonWebTokenService;
use Application\Service\LoginService;
use Application\Tests\Helper\ControllerHelperTrait;
use Application\Tests\Helper\UserHelperTrait;
use Eureka\Component\Password\Password;
use Eureka\Component\Password\PasswordChecker;
use Eureka\Kernel\Http\Exception\HttpBadRequestException;
use Eureka\Kernel\Http\Exception\HttpForbiddenException;
use Eureka\Kernel\Http\Exception\HttpUnauthorizedException;
use Lcobucci\Clock\SystemClock;
use PHPUnit\Framework\TestCase;

/**
 * Class HealthControllerTest
 *
 * @author Romain Cottard
 */
class TokenControllerTest extends TestCase
{
    use ControllerHelperTrait;
    use UserHelperTrait;

    /**
     * @return void
     * @throws \Exception
     */
    public function testICanGetTokenWhenIGiveCorrectCredentials(): void
    {
        $body = ['email' => 'email', 'password' => 'password'];
        $serverRequest = $this->getServerRequest('/auth/token/get', 'POST', [], $body);

        $controller = $this->getTokenController();
        $response   = $controller->get($serverRequest);
        $json       = $this->getJsonObjectFromResponse($response);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertTrue(isset($json->data->token));
        $this->assertNotEmpty($json->data->token);
    }

    /**
     * @return void
     * @throws \Exception
     */
    public function testIHaveAnErrorWhenIGiveIncorrectEmail(): void
    {
        $body = ['email' => 'another_email', 'password' => 'password'];

        $serverRequest = $this->getServerRequest('/auth/token/get', 'POST', [], $body);
        $controller    = $this->getTokenController();

        $this->expectExceptionCode(1202);
        $this->expectExceptionMessage('Invalid email or password');
        $this->expectException(HttpUnauthorizedException::class);
        $controller->get($serverRequest);
    }

    /**
     * @return void
     * @throws \Exception
     */
    public function testIHaveAnErrorWhenIGiveIncorrectPassword(): void
    {
        $body = ['email' => 'email', 'password' => 'another_password'];

        $serverRequest = $this->getServerRequest('/auth/token/get', 'POST', [], $body);
        $controller    = $this->getTokenController();

        $this->expectExceptionCode(1202);
        $this->expectExceptionMessage('Invalid email or password');
        $this->expectException(HttpUnauthorizedException::class);
        $controller->get($serverRequest);
    }

    /**
     * @return void
     * @throws \Exception
     */
    public function testIHaveAnErrorWhenIGiveEmptyEmail(): void
    {
        $body = ['email' => '', 'password' => 'password'];

        $serverRequest = $this->getServerRequest('/auth/token/get', 'POST', [], $body);
        $controller    = $this->getTokenController();

        $this->expectExceptionCode(1200);
        $this->expectExceptionMessage('Error with email (empty or not well formatted value)');
        $this->expectException(HttpBadRequestException::class);
        $controller->get($serverRequest);
    }

    /**
     * @return void
     * @throws \Exception
     */
    public function testIHaveAnErrorWhenIGiveEmptyPassword(): void
    {
        $body = ['email' => 'email'];

        $serverRequest = $this->getServerRequest('/auth/token/get', 'POST', [], $body);
        $controller    = $this->getTokenController();

        $this->expectExceptionCode(1201);
        $this->expectExceptionMessage('Error with password (empty or not well formatted value)');
        $this->expectException(HttpBadRequestException::class);
        $controller->get($serverRequest);
    }

    /**
     * @return void
     * @throws \Exception
     */
    public function testIHaveAnErrorWhenIGiveCredentialForUserDisabled(): void
    {
        $body = ['email' => 'email', 'password' => 'password'];
        $serverRequest = $this->getServerRequest('/auth/token/get', 'POST', [], $body);

        $controller = $this->getTokenController(false);

        $this->expectExceptionCode(1203);
        $this->expectExceptionMessage('Account disabled');
        $this->expectException(HttpForbiddenException::class);
        $controller->get($serverRequest);
    }

    /**
     * @return void
     * @throws \Exception
     */
    public function testICanVerifyWhenIGiveTokenInHeaders(): void
    {
        $headers = [
            'Authorization' => 'JWT ' . $this->getUserToken('ThisIsALongSecretKeyWith32Chars!', 1)->toString(),
        ];
        $serverRequest = $this->getServerRequest('/auth/token/verify', 'POST', [], [], $headers);

        $controller = $this->getTokenController();
        $response   = $controller->verify($serverRequest);
        $json       = $this->getJsonObjectFromResponse($response);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertTrue(isset($json->data->valid));
        $this->assertTrue(isset($json->data->expired));
        $this->assertTrue($json->data->valid);
        $this->assertFalse($json->data->expired);
    }


    /**
     * @return void
     * @throws \Exception
     */
    public function testIHaveAnErrorWhenIGiveBadFormattedTokenInHeaders(): void
    {
        $headers = [
            'Authorization' => 'BadFormattedHeader ' . $this->getUserToken('ThisIsALongSecretKeyWith32Chars!', 1)->toString(),
        ];
        $serverRequest = $this->getServerRequest('/auth/token/verify', 'POST', [], [], $headers);
        $controller    = $this->getTokenController();

        $this->expectExceptionCode(1060);
        $this->expectExceptionMessage('Invalid Authorization: Token not provided');
        $this->expectException(HttpBadRequestException::class);
        $controller->verify($serverRequest);
    }

    /**
     * @param bool $userIsEnabled
     * @return LoginService
     */
    private function getLoginServiceMock(bool $userIsEnabled = true): LoginService
    {
        $user = $this->getUser((object) [
            'user_id'         => 1,
            'user_is_enabled' => $userIsEnabled,
            'user_email'      => 'email',
            'user_password'   => (new Password('password'))->getHash(),
        ]);

        return new LoginService(
            new JsonWebTokenService($this->getJWTConfiguration('ThisIsALongSecretKeyWith32Chars!')),
            $this->getUserRepositoryMock($user),
            new PasswordChecker()
        );
    }

    /**
     * @param bool $userIsEnabled
     * @return TokenController
     */
    private function getTokenController(bool $userIsEnabled = true): TokenController
    {
        $controller = new TokenController(
            new JsonWebTokenService($this->getJWTConfiguration('ThisIsALongSecretKeyWith32Chars!')),
            $this->getLoginServiceMock($userIsEnabled),
            new SystemClock(new \DateTimeZone('UTC'))
        );

        /** @var TokenController $controller */
        $controller = $this->addFactoriesToController($controller);

        return $controller;
    }
}
