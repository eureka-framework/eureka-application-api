<?php

/*
 * Copyright (c) Romain Cottard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace Application\Behat\Context\Authorization;

use Application\Behat\Mock\UserTrait;
use Application\Behat\Helper\ServiceMockAwareTrait;
use Behat\Behat\Context\Context;

/**
 * Class AuthorizationContext
 *
 * @author Romain Cottard
 */
class AuthorizationContext implements Context
{
    use UserTrait;
    use ServiceMockAwareTrait;
}
