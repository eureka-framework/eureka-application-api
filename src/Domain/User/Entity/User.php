<?php

/*
 * Copyright (c) Romain Cottard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace Application\Domain\User\Entity;

use Eureka\Component\Orm\EntityInterface;
use Lcobucci\JWT\Token;
use Safe\Exceptions\JsonException;

use function Safe\json_decode;
use function Safe\json_encode;

/**
 * DataMapper Data class for table "user"
 *
 * @author Eureka Orm Generator
 */
class User extends Abstracts\AbstractUser implements EntityInterface
{
    /** @var int MAX_ACTIVE_TOKEN_KEPT */
    private const MAX_ACTIVE_TOKEN_KEPT = 10;

    /**
     * @return string[]
     */
    public function getTokenHashListDecoded(): array
    {
        $tokenHashList = $this->getTokenHashList();

        //~ Try to decode list
        try {
            $tokenHashList = json_decode($tokenHashList);
        } catch (JsonException) {
            return [];
        }

        if (!is_array($tokenHashList)) {
            $tokenHashList = [];
        }

        return $tokenHashList;
    }

    /**
     * @return void
     */
    public function resetAccessTokenList(): void
    {
        $this->setTokenHashList('[]');
    }

    /**
     * @param Token $token
     * @return void
     * @throws JsonException
     */
    public function revokeToken(Token $token): void
    {
        $tokenList = $this->getTokenHashListDecoded();
        $key = array_search(md5($token->toString()), $tokenList);

        if ($key !== false) {
            unset($tokenList[$key]);
            $this->setTokenHashList(json_encode($tokenList));
        }
    }

    /**
     * @param Token $token
     * @return bool
     */
    public function hasRegisteredToken(Token $token): bool
    {
        $hash = md5($token->toString());

        return in_array($hash, $this->getTokenHashListDecoded());
    }

    /**
     * @param Token $token
     * @return User
     * @throws JsonException
     */
    public function registerToken(Token $token): self
    {
        //~ Add token to list
        $accessTokenList   = $this->getTokenHashListDecoded();
        $accessTokenList[] = md5($token->toString());

        //~ Remove the oldest token if necessary
        if (count($accessTokenList) > self::MAX_ACTIVE_TOKEN_KEPT) {
            array_shift($accessTokenList);
        }

        //~ Set json_encode list into entity
        $this->setTokenHashList(json_encode($accessTokenList));

        return $this;
    }

    /**
     * @param Token $token
     * @return $this
     * @throws JsonException
     */
    public function unregisterToken(Token $token): self
    {
        $tokenHashList = $this->getTokenHashListDecoded();

        //~ Search and remove token hash from list
        $hash = md5($token->toString());
        $key  = array_search($hash, $tokenHashList);

        if ($key === false) {
            return $this;
        }

        unset($tokenHashList[$key]);

        //~ Set json_encode list into entity
        $this->setTokenHashList(json_encode($tokenHashList));

        return $this;
    }

    /**
     * @return string
     */
    public function __toString()
    {
        return $this->email;
    }
}
