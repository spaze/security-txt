<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Validator\Validators;

use Spaze\SecurityTxt\Exceptions\SecurityTxtNoContactError;
use Spaze\SecurityTxt\SecurityTxt;

class ContactMissingFieldValidator implements FieldValidator
{

	/**
	 * @throws SecurityTxtNoContactError
	 */
	public function validate(SecurityTxt $securityTxt): void
	{
		if (!$securityTxt->getContact()) {
			throw new SecurityTxtNoContactError();
		}
	}

}
