<?php

/*
 * Copyright (c) Romain Cottard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace Application\Behat\Context\Authentication;

use Application\Behat\Mock\UserTrait;
use Application\Behat\Helper\JsonWebTokenServiceAwareTrait;
use Application\Behat\Helper\ServiceMockAwareTrait;
use Behat\Behat\Context\Context;

/**
 * Class TokenRevokeContext
 *
 * @author Romain Cottard
 */
class TokenRevokeContext implements Context
{
    use JsonWebTokenServiceAwareTrait;
    use ServiceMockAwareTrait;
    use UserTrait;
}
