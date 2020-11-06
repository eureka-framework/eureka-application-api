<?php

/*
 * Copyright (c) Romain Cottard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace Application\Behat\Fixture;

use Application\Behat\Context\Common\ClientApplicationContext;
use Application\Domain\User\Entity\User;
use Application\Domain\User\Repository\UserRepositoryInterface;
use Eureka\Component\Password\Password;
use Eureka\Component\Orm\Exception\EntityNotExistsException;
use Eureka\Component\Validation\Entity\ValidatorEntityFactory;
use Eureka\Component\Validation\ValidatorFactory;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Rule\AnyInvokedCount;

/**
 * Trait UserTrait
 *
 * @author Romain Cottard
 */
trait UserTrait
{
    /** @var UserRepositoryInterface|MockObject $repository */
    private UserRepositoryInterface $repository;

    /** @var ValidatorFactory $validatorFactory */
    private ValidatorFactory $validatorFactory;

    /** @var ValidatorEntityFactory $validatorEntityFactory */
    private ValidatorEntityFactory $validatorEntityFactory;

    /**
     * @BeforeScenario
     *
     * @throws \Exception
     */
    public function initializeUserRepository()
    {
        $this->registerMockService(
            UserRepositoryInterface::class,
            'persist',
            true
        );

        $container = ClientApplicationContext::getContainer();

        $this->repository             = $container->get('Application\Domain\User\Repository\UserRepositoryInterface');
        $this->validatorFactory       = $container->get('Eureka\Component\Validation\ValidatorFactory');
        $this->validatorEntityFactory = $container->get('Eureka\Component\Validation\Entity\ValidatorEntityFactory');
    }

    /**
     * @BeforeScenario @fixtureNoUserId00
     */
    public function fixtureNoUserId00(): void
    {
        $this->repository
            ->expects(new AnyInvokedCount())
            ->method('findById')
            ->with(0)
            ->willThrowException(new EntityNotExistsException())
        ;

        $this->repository
            ->expects(new AnyInvokedCount())
            ->method('findByEmail')
            ->with('user_unknown@example.com')
            ->willThrowException(new EntityNotExistsException())
        ;
    }


    /**
     * @BeforeScenario @fixtureNoUserTest
     */
    public function fixtureNoUserTest(): void
    {
        $this->repository
            ->expects(new AnyInvokedCount())
            ->method('findByEmail')
            ->with('user_test@example.com')
            ->willThrowException(new EntityNotExistsException())
        ;
    }

    /**
     * @BeforeScenario @fixtureUserId02
     */
    public function fixtureUserId02(): void
    {
        $entity = $this->getUser02();

        $this->repository
            ->expects(new AnyInvokedCount())
            ->method('findById')
            ->with(2)
            ->willReturn($entity)
        ;

        $this->repository
            ->expects(new AnyInvokedCount())
            ->method('findByEmail')
            ->with('user_enabled@example.com')
            ->willReturn($entity)
        ;
    }

    /**
     * @BeforeScenario @fixtureUserId03
     */
    public function fixtureUserId03(): void
    {
        $entity = $this->getUser03();

        $this->repository
            ->expects(new AnyInvokedCount())
            ->method('findById')
            ->with(3)
            ->willReturn($entity)
        ;

        $this->repository
            ->expects(new AnyInvokedCount())
            ->method('findByEmail')
            ->with('user_disabled@example.com')
            ->willReturn($entity)
        ;
    }

    /**
     * @return User
     */
    private function getUser02(): User
    {
        $entity = new User($this->repository, $this->validatorFactory, $this->validatorEntityFactory);
        $entity->setId(2);
        $entity->setEmail('user_enabled@example.com');
        $entity->setPassword((new Password('password02'))->getHash());
        $entity->setFirstName('User 2');
        $entity->setIsEnabled(true);
        $entity->setDateCreate('2020-01-01 00:00:00');

        return $entity;
    }

    /**
     * @return User
     */
    private function getUser03(): User
    {
        $entity = new User($this->repository, $this->validatorFactory, $this->validatorEntityFactory);
        $entity->setId(3);
        $entity->setEmail('user_disabled@example.com');
        $entity->setPassword((new Password('password03'))->getHash());
        $entity->setFirstName('User 3');
        $entity->setIsEnabled(false);
        $entity->setDateCreate('2020-01-01 00:00:00');

        return $entity;
    }
}
