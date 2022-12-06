<?php

/*
 * Copyright (c) Romain Cottard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace Application\Domain\User\Repository;

use Application\Domain\User\Entity\User;
use Eureka\Component\Orm\EntityInterface;
use Eureka\Component\Orm\Exception\EntityNotExistsException;
use Eureka\Component\Orm\Exception\InvalidQueryException;
use Eureka\Component\Orm\Exception\OrmException;
use Eureka\Component\Orm\RepositoryInterface;

/**
 * User repository interface.
 *
 * @author Eureka Orm Generator
 */
interface UserRepositoryInterface extends RepositoryInterface
{
    /**
     * @param string $email
     * @return User&EntityInterface
     * @throws EntityNotExistsException
     * @throws InvalidQueryException
     * @throws OrmException
     */
    public function findByEmail(string $email): User;

    /**
     * @param int $id
     * @return User&EntityInterface
     * @throws EntityNotExistsException
     */
    public function findById(int $id);

    /**
     * @param \stdClass|null $row
     * @param bool $exists
     * @return User&EntityInterface
     */
    public function newEntity(\stdClass $row = null, bool $exists = false);
}
