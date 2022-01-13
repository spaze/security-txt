<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Validator\Validators;

use Spaze\SecurityTxt\Exceptions\SecurityTxtNoExpiresError;
use Spaze\SecurityTxt\SecurityTxt;

class ExpiresMissingFieldValidator implements FieldValidator
{

	/**
	 * @throws SecurityTxtNoExpiresError
	 */
	public function validate(SecurityTxt $securityTxt): void
	{
		if (!$securityTxt->getExpires()) {
			throw new SecurityTxtNoExpiresError();
		}
	}

}
