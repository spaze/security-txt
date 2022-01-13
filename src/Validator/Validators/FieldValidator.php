<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Validator\Validators;

use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\SecurityTxt;

interface FieldValidator
{

	/**
	 * @throws SecurityTxtError
	 */
	public function validate(SecurityTxt $securityTxt): void;

}
