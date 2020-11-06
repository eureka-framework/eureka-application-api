<?php

/*
 * Copyright (c) Romain Cottard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace Application\Behat\Context\Application;

use Application\Behat\Helper;
use Behat\Behat\Context\Context;

/**
 * Class TokenGetContext
 *
 * @author Romain Cottard
 */
class HealthContext implements Context
{
    use Helper\ServiceMockAwareTrait;
}
