<?php

/*
 * Copyright (c) Romain Cottard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace Application\Tests\Middleware;

use Application\Domain\User\Entity\User;
use Application\Middleware\AuthenticationMiddleware;
use Application\Service\JsonWebTokenService;
use Application\Tests\Helper\ControllerHelperTrait;
use Application\Tests\Helper\UserHelperTrait;
use Eureka\Kernel\Http\Exception\HttpBadRequestException;
use Eureka\Kernel\Http\Exception\HttpForbiddenException;
use Eureka\Kernel\Http\Exception\HttpUnauthorizedException;
use Eureka\Component\Orm\Exception\OrmException;
use Lcobucci\Clock\SystemClock;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Safe\Exceptions\JsonException;

use function Safe\json_encode;

/**
 * Class AuthenticationMiddlewareTest
 *
 * @author Romain Cottard
 */
class AuthenticationMiddlewareTest extends TestCase
{
    use ControllerHelperTrait;
    use UserHelperTrait;

    /**
     * @return void
     * @throws HttpUnauthorizedException
     * @throws HttpBadRequestException
     * @throws OrmException
     * @throws JsonException
     */
    public function testICanPassThroughMiddlewareWhenNoAuthenticationIsRequired(): void
    {
        $middleware = $this->getMiddleware();

        $mockResponse = $this->getMockBuilder(ResponseInterface::class)->getMock();
        $mockHandler  = $this->getMockBuilder(RequestHandlerInterface::class)->getMock();
        $mockHandler->method('handle')->willReturn($mockResponse);

        $serverRequest = $this->getServerRequest('/');

        /** @var RequestHandlerInterface $mockHandler */
        $response = $middleware->process(
            $serverRequest,
            $mockHandler
        );

        $this->assertInstanceOf(ResponseInterface::class, $response);
    }

    /**
     * @return void
     * @throws HttpUnauthorizedException
     * @throws HttpBadRequestException
     * @throws OrmException
     * @throws JsonException
     * @throws \Exception
     */
    public function testICanPassThroughMiddlewareWhenAuthenticationIsRequiredAndValidTokenIsProvided(): void
    {
        $token = $this->getUserToken('ThisIsALongSecretKeyWith32Chars!', 1);
        $user  = $this->getUser((object) [
            'user_id'              => 1,
            'user_is_enabled'      => true,
            'user_token_hash_list' => json_encode([md5($token->toString())]),
        ]);

        $middleware = $this->getMiddleware($user);

        $mockResponse = $this->getMockBuilder(ResponseInterface::class)->getMock();
        $mockHandler  = $this->getMockBuilder(RequestHandlerInterface::class)->getMock();
        $mockHandler->method('handle')->willReturn($mockResponse);

        $serverRequest = $this->getServerRequest('/')
            ->withAttribute('authenticationRequired', true)
            ->withAddedHeader('Authorization', 'JWT ' . $token->toString())
        ;

        /** @var RequestHandlerInterface $mockHandler */
        $response = $middleware->process(
            $serverRequest,
            $mockHandler
        );

        $this->assertInstanceOf(ResponseInterface::class, $response);
    }

    /**
     * @return void
     * @throws HttpUnauthorizedException
     * @throws HttpBadRequestException
     * @throws OrmException
     * @throws JsonException
     */
    public function testHaveAnExceptionWhenAuthenticationIsRequiredAndNoTokenIsProvided(): void
    {
        $middleware = $this->getMiddleware();

        $mockResponse = $this->getMockBuilder(ResponseInterface::class)->getMock();
        $mockHandler  = $this->getMockBuilder(RequestHandlerInterface::class)->getMock();
        $mockHandler->method('handle')->willReturn($mockResponse);

        $serverRequest = $this->getServerRequest('/')
            ->withAttribute('authenticationRequired', true)
        ;

        /** @var RequestHandlerInterface $mockHandler */
        $this->expectException(HttpBadRequestException::class);
        $this->expectExceptionCode(1060);
        $this->expectExceptionMessage('Invalid Authorization: Token not provided');
        $middleware->process(
            $serverRequest,
            $mockHandler
        );
    }

    /**
     * @return void
     * @throws HttpUnauthorizedException
     * @throws HttpBadRequestException
     * @throws OrmException
     * @throws JsonException
     * @throws \Exception
     */
    public function testHaveAnExceptionWhenAuthenticationIsRequiredAndBadTokenIsProvided(): void
    {
        $token = $this->getUserToken('ThisIsABadSecretKeyWith32Chars!!', 1);
        $user  = $this->getUser((object) [
            'user_id'              => 1,
            'user_is_enabled'      => true,
            'user_token_hash_list' => json_encode([md5($token->toString())]),
        ]);

        $middleware = $this->getMiddleware($user);

        $mockResponse = $this->getMockBuilder(ResponseInterface::class)->getMock();
        $mockHandler  = $this->getMockBuilder(RequestHandlerInterface::class)->getMock();
        $mockHandler->method('handle')->willReturn($mockResponse);

        $serverRequest = $this->getServerRequest('/')
            ->withAttribute('authenticationRequired', true)
            ->withAddedHeader('Authorization', 'JWT ' . $token->toString())
        ;

        /** @var RequestHandlerInterface $mockHandler */
        $this->expectException(HttpBadRequestException::class);
        $this->expectExceptionCode(1051);
        $this->expectExceptionMessage('Token is not valid');
        $middleware->process(
            $serverRequest,
            $mockHandler
        );
    }

    /**
     * @return void
     * @throws HttpUnauthorizedException
     * @throws HttpBadRequestException
     * @throws OrmException
     * @throws JsonException
     * @throws \Exception
     */
    public function testHaveAnExceptionWhenAuthenticationIsRequiredAndExpiredTokenIsProvided(): void
    {
        $token = $this->getUserToken('ThisIsALongSecretKeyWith32Chars!', 1, (time() - 1000000));
        $user  = $this->getUser((object) [
            'user_id'              => 1,
            'user_is_enabled'      => true,
            'user_token_hash_list' => json_encode([md5($token->toString())]),
        ]);

        $middleware = $this->getMiddleware($user);

        $mockResponse = $this->getMockBuilder(ResponseInterface::class)->getMock();
        $mockHandler  = $this->getMockBuilder(RequestHandlerInterface::class)->getMock();
        $mockHandler->method('handle')->willReturn($mockResponse);

        $serverRequest = $this->getServerRequest('/')
            ->withAttribute('authenticationRequired', true)
            ->withAddedHeader('Authorization', 'JWT ' . $token->toString())
        ;

        /** @var RequestHandlerInterface $mockHandler */
        $this->expectException(HttpUnauthorizedException::class);
        $this->expectExceptionCode(1050);
        $this->expectExceptionMessage('Token is expired');
        $middleware->process(
            $serverRequest,
            $mockHandler
        );
    }

    /**
     * @return void
     * @throws HttpUnauthorizedException
     * @throws HttpBadRequestException
     * @throws OrmException
     * @throws JsonException
     * @throws \Exception
     */
    public function testHaveAnExceptionWhenAuthenticationIsRequiredAndUserInTokenDoesNotExist(): void
    {
        $token = $this->getUserToken('ThisIsALongSecretKeyWith32Chars!', 2);
        $user  = $this->getUser((object) [
            'user_id'              => 1,
            'user_is_enabled'      => true,
            'user_token_hash_list' => json_encode([md5($token->toString())]),
        ]);

        $middleware = $this->getMiddleware($user);

        $mockResponse = $this->getMockBuilder(ResponseInterface::class)->getMock();
        $mockHandler  = $this->getMockBuilder(RequestHandlerInterface::class)->getMock();
        $mockHandler->method('handle')->willReturn($mockResponse);

        $serverRequest = $this->getServerRequest('/')
            ->withAttribute('authenticationRequired', true)
            ->withAddedHeader('Authorization', 'JWT ' . $token->toString())
        ;

        /** @var RequestHandlerInterface $mockHandler */
        $this->expectException(HttpUnauthorizedException::class);
        $this->expectExceptionCode(1054);
        $this->expectExceptionMessage('User not found');
        $middleware->process(
            $serverRequest,
            $mockHandler
        );
    }

    /**
     * @return void
     * @throws HttpUnauthorizedException
     * @throws HttpBadRequestException
     * @throws OrmException
     * @throws JsonException
     * @throws \Exception
     */
    public function testHaveAnExceptionWhenAuthenticationIsRequiredAndUserInTokenIsDisabled(): void
    {
        $token = $this->getUserToken('ThisIsALongSecretKeyWith32Chars!', 1);
        $user  = $this->getUser((object) [
            'user_id'              => 1,
            'user_is_enabled'      => false,
            'user_token_hash_list' => json_encode([md5($token->toString())]),
        ]);

        $middleware = $this->getMiddleware($user);

        $mockResponse = $this->getMockBuilder(ResponseInterface::class)->getMock();
        $mockHandler  = $this->getMockBuilder(RequestHandlerInterface::class)->getMock();
        $mockHandler->method('handle')->willReturn($mockResponse);

        $serverRequest = $this->getServerRequest('/')
            ->withAttribute('authenticationRequired', true)
            ->withAddedHeader('Authorization', 'JWT ' . $token->toString())
        ;

        /** @var RequestHandlerInterface $mockHandler */
        $this->expectException(HttpForbiddenException::class);
        $this->expectExceptionCode(1052);
        $this->expectExceptionMessage('Account is disabled');
        $middleware->process(
            $serverRequest,
            $mockHandler
        );
    }

    /**
     * @return void
     * @throws HttpUnauthorizedException
     * @throws HttpBadRequestException
     * @throws OrmException
     * @throws JsonException
     * @throws \Exception
     */
    public function testHaveAnExceptionWhenAuthenticationIsRequiredAndTokenIsNotInRegisteredToken(): void
    {
        $token = $this->getUserToken('ThisIsALongSecretKeyWith32Chars!', 1);
        $user  = $this->getUser((object) [
            'user_id'              => 1,
            'user_is_enabled'      => true,
            'user_token_hash_list' => json_encode([md5('toto')]),
        ]);

        $middleware = $this->getMiddleware($user);

        $mockResponse = $this->getMockBuilder(ResponseInterface::class)->getMock();
        $mockHandler  = $this->getMockBuilder(RequestHandlerInterface::class)->getMock();
        $mockHandler->method('handle')->willReturn($mockResponse);

        $serverRequest = $this->getServerRequest('/')
            ->withAttribute('authenticationRequired', true)
            ->withAddedHeader('Authorization', 'JWT ' . $token->toString())
        ;

        /** @var RequestHandlerInterface $mockHandler */
        $this->expectException(HttpUnauthorizedException::class);
        $this->expectExceptionCode(1053);
        $this->expectExceptionMessage('Unknown or Revoked token');
        $middleware->process(
            $serverRequest,
            $mockHandler
        );
    }

    /**
     * @param User|null $user
     * @return AuthenticationMiddleware
     */
    private function getMiddleware(User $user = null): AuthenticationMiddleware
    {
        if ($user === null) {
            $user = $this->getUser((object) [
                'user_id'         => 1,
                'user_is_enabled' => true,
            ]);
        }

        return new AuthenticationMiddleware(
            new JsonWebTokenService($this->getJWTConfiguration('ThisIsALongSecretKeyWith32Chars!')),
            $this->getUserRepositoryMock($user),
            (new SystemClock(new \DateTimeZone('UTC')))
        );
    }
}
