<?php

/*
 * Copyright (c) Romain Cottard
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace Application\Behat\Helper;

use JsonSchema\Validator;
use PHPUnit\Framework\Assert;

/**
 * Trait SchemaValidatorTrait
 *
 * @author Romain Cottard
 */
trait JsonSchemaValidatorTrait
{
    /**
     * @param \stdClass $schema
     * @param \stdClass $item
     * @return void
     */
    protected function assertItemIsValid(\stdClass $schema, \stdClass $item): void
    {
        $validator = new Validator();
        $validator->validate($item, $schema);
        $validator->isValid();

        $this->assertNoErrorsInValidator($validator);
    }

    /**
     * @param \stdClass $schema
     * @param \stdClass[] $items
     * @return void
     */
    protected function assertItemsAreValid(\stdClass $schema, array $items): void
    {
        $validator = new Validator();

        foreach ($items as $item) {
            $validator->validate($item, $schema);
            $validator->isValid();
        }

        $this->assertNoErrorsInValidator($validator);
    }

    /**
     * @param Validator $validator
     * @return void
     */
    private function assertNoErrorsInValidator(Validator $validator): void
    {
        if (empty($validator->getErrors())) {
            Assert::assertTrue(true, 'Schema is valid!');
            return;
        }

        $errors = [];
        foreach ($validator->getErrors() as $error) {
            $errors[] = 'Error on property ' . $error['property'] . ': ' . $error['message'];
        }

        Assert::assertTrue(false, implode("\n", $errors));
    }
}
