<?php

/*
 * Copyright (c) Romain Cottard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace Application\Tests\Helper;

use Application\Domain\User\Entity\User;
use Application\Domain\User\Infrastructure\Mapper\UserMapper;
use Application\Domain\User\Repository\UserRepositoryInterface;
use Application\Service\JsonWebTokenService;
use Eureka\Component\Database\Connection;
use Eureka\Component\Database\ConnectionFactory;
use Eureka\Component\Orm\Exception\EntityNotExistsException;
use Eureka\Component\Validation\ValidatorFactory;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use PHPUnit\Framework\MockObject\MockBuilder;

/**
 * Trait UserHelperTrait
 *
 * @author Romain Cottard
 */
trait UserHelperTrait
{
    abstract public function getMockBuilder(string $className): MockBuilder;

    protected function getConnectionMock(): Connection
    {
        return $this->getMockBuilder(Connection::class)->disableOriginalConstructor()->getMock();
    }

    protected function getConnectionFactoryMock(): ConnectionFactory
    {
        $mock = $this->getMockBuilder(ConnectionFactory::class)->disableOriginalConstructor()->getMock();
        $mock->method('getConnection')->willReturn($this->getConnectionMock());

        return $mock;
    }

    /**
     * @param \stdClass $data User data to set
     * @return User
     */
    protected function getUser(\stdClass $data): User
    {
        $userRepository = new UserMapper(
            'common',
            $this->getConnectionFactoryMock(),
            new ValidatorFactory()
        );

        /** @var User $user */
        $user = $userRepository->newEntity($data);

        return $user;
    }

    /**
     * @param User $user
     * @return UserRepositoryInterface
     */
    protected function getUserRepositoryMock(User $user): UserRepositoryInterface
    {
        $userRepositoryMock = $this->getMockBuilder(UserRepositoryInterface::class)->getMock();

        //~ Mock findByEmail()
        $userRepositoryMock->method('findByEmail')
            ->willReturnCallback(function ($email) use ($user) {

                if ($email !== 'email') {
                    throw new EntityNotExistsException();
                }

                return $user;
            })
        ;

        //~ Mock findById()
        $userRepositoryMock->method('findById')
            ->willReturnCallback(function ($userId) use ($user) {

                if ($userId !== $user->getId()) {
                    throw new EntityNotExistsException();
                }

                return $user;
            })
        ;

        return $userRepositoryMock;
    }

    /**
     * @param string $key
     * @param int $userId
     * @param int|null $time
     * @return Token
     * @throws \Exception
     */
    private function getUserToken(string $key, int $userId, int $time = null): Token
    {
        if (empty($time)) {
            $time = time();
        }

        return (new JsonWebTokenService($this->getJWTConfiguration($key)))->generateToken($userId, $time);
    }

    private function getJWTConfiguration(string $secretKey): Configuration
    {
        $signer = new Sha256();
        $key    = InMemory::plainText($secretKey ?: 'test');

        $configuration = Configuration::forSymmetricSigner($signer, $key);
        $configuration->setValidationConstraints(new SignedWith($signer, $key));

        return $configuration;
    }
}
