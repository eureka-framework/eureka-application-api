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
use Eureka\Component\Orm\Exception\OrmException;

/**
 * Trait UserTrait
 *
 * @author Romain Cottard
 */
trait UserTrait
{
    /** @var UserRepositoryInterface $repository */
    private UserRepositoryInterface $repository;

    /**
     * @BeforeScenario
     *
     * @throws \Exception
     */
    public function initializeUserRepository()
    {
        $this->repository = ClientApplicationContext::getContainer()->get('Application\Domain\User\Repository\UserRepositoryInterface');
    }

    /**
     * @BeforeScenario @fixtureNoUserId00
     * @throws OrmException
     */
    public function fixtureNoUserId00(): void
    {
        //~ Try by id
        try {
            $entity = $this->repository->findById(0);
            $this->repository->delete($entity);
        } catch(EntityNotExistsException $exception) {
            //~ What is expected, do nothing more
        }

        //~ Try by email
        try {
            $entity = $this->repository->findByEmail('');
            $this->repository->delete($entity);
        } catch(EntityNotExistsException $exception) {
            //~ What is expected, do nothing more
        }
    }


    /**
     * @BeforeScenario @fixtureNoUserTest
     * @throws OrmException
     */
    public function fixtureNoUserTest(): void
    {
        //~ Try by email
        try {
            $entity = $this->repository->findByEmail('user_test@example.com');
            $this->repository->delete($entity);
        } catch(EntityNotExistsException $exception) {
            //~ What is expected, do nothing more
        }
    }

    /**
     * @BeforeScenario @fixtureUserId02
     * @throws OrmException
     */
    public function fixtureUserId02(): void
    {
        //~ Try by id
        try {
            $entity = $this->repository->findById(2);
        } catch(EntityNotExistsException $exception) {
            //~ Try by email
            try {
                $entity = $this->repository->findByEmail('user_enabled@example.com');
            } catch (EntityNotExistsException $exception) {
                $entity = $this->repository->newEntity();
            }
        }

        $this->repository->persist($this->getUser02($entity));
    }

    /**
     * @BeforeScenario @fixtureUserId03
     * @throws OrmException
     */
    public function fixtureUserId03(): void
    {
        //~ Try by id
        try {
            $entity = $this->repository->findById(3);
        } catch(EntityNotExistsException $exception) {
            //~ Try by email
            try {
                $entity = $this->repository->findByEmail('user_disabled@example.com');
            } catch (EntityNotExistsException $exception) {
                $entity = $this->repository->newEntity();
            }
        }

        $this->repository->persist($this->getUser03($entity));
    }

    /**
     * @param User $entity
     * @return User
     */
    private function getUser02(User $entity): User
    {
        $entity->setId(2);
        $entity->setEmail('user_enabled@example.com');
        $entity->setPassword((new Password('password02'))->getHash());
        $entity->setFirstName('User 2');
        $entity->setIsEnabled(true);
        $entity->setDateCreate('2020-01-01 00:00:00');

        return $entity;
    }

    /**
     * @param User $entity
     * @return User
     */
    private function getUser03(User $entity): User
    {
        $entity->setId(3);
        $entity->setEmail('user_disabled@example.com');
        $entity->setPassword((new Password('password03'))->getHash());
        $entity->setFirstName('User 3');
        $entity->setIsEnabled(false);
        $entity->setDateCreate('2020-01-01 00:00:00');

        return $entity;
    }
}
