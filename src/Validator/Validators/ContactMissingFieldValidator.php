<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Validator\Validators;

use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\SecurityTxt;
use Spaze\SecurityTxt\Violations\SecurityTxtNoContact;

class ContactMissingFieldValidator implements FieldValidator
{

	/**
	 * @throws SecurityTxtError
	 */
	public function validate(SecurityTxt $securityTxt): void
	{
		if (!$securityTxt->getContact()) {
			throw new SecurityTxtError(new SecurityTxtNoContact());
		}
	}

}
