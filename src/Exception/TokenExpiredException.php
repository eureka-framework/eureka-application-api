<?php

/*
 * Copyright (c) Romain Cottard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace Application\Exception;

use Eureka\Kernel\Http\Exception\HttpUnauthorizedException;

/**
 * Class TokenExpiredException
 *
 * @author Catalog Team
 */
class TokenExpiredException extends HttpUnauthorizedException
{
}
