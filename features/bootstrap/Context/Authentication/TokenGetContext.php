<?php

/*
 * Copyright (c) Romain Cottard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace Application\Behat\Context\Authentication;

use Application\Behat\Context\Common\ClientApplicationContext;
use Application\Behat\Fixture\UserTrait;
use Application\Behat\Helper\JsonWebTokenServiceAwareTrait;
use Application\Behat\Helper\ServiceMockAwareTrait;
use Behat\Behat\Context\Context;
use PHPUnit\Framework\Assert;

/**
 * Class TokenGetContext
 *
 * @author Romain Cottard
 */
class TokenGetContext implements Context
{
    use JsonWebTokenServiceAwareTrait;
    use ServiceMockAwareTrait;
    use UserTrait;

    /**
     * @Then I get a valid token
     *
     * @return void
     */
    public function iGetAValidToken()
    {
        $content = ClientApplicationContext::getResponseContentObject();

        Assert::assertTrue(!empty($content->data->token));

        $this->assertTokenIsValid($content->data->token);
    }
}
