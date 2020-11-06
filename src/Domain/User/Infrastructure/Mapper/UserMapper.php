<?php

/*
 * Copyright (c) Romain Cottard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace Application\Domain\User\Infrastructure\Mapper;

use Application\Domain\User\Repository\UserRepositoryInterface;
use Application\Domain\User\Entity\User;
use Eureka\Component\Orm\EntityInterface;
use Eureka\Component\Orm\Exception\EntityNotExistsException;
use Eureka\Component\Orm\Exception\InvalidQueryException;
use Eureka\Component\Orm\Exception\OrmException;
use Eureka\Component\Orm\Query\SelectBuilder;

/**
 * Mapper class for table "user"
 *
 * @author Eureka Orm Generator
 */
class UserMapper extends Abstracts\AbstractUserMapper implements UserRepositoryInterface
{
    /**
     * @param string $email
     * @return User|EntityInterface
     * @throws EntityNotExistsException
     * @throws InvalidQueryException
     * @throws OrmException
     */
    public function findByEmail(string $email): User
    {
        $queryBuilder = new SelectBuilder($this);
        $queryBuilder->addWhere('user_email', $email);

        return $this->selectOne($queryBuilder);
    }
}
