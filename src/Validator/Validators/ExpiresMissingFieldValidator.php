<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Validator\Validators;

use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\SecurityTxt;
use Spaze\SecurityTxt\Violations\SecurityTxtNoExpires;

class ExpiresMissingFieldValidator implements FieldValidator
{

	/**
	 * @throws SecurityTxtError
	 */
	public function validate(SecurityTxt $securityTxt): void
	{
		if (!$securityTxt->getExpires()) {
			throw new SecurityTxtError(new SecurityTxtNoExpires());
		}
	}

}
