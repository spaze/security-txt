<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Validator\Validators;

use Spaze\SecurityTxt\Exceptions\SecurityTxtSignedButNoCanonicalWarning;
use Spaze\SecurityTxt\SecurityTxt;

class SignedButCanonicalMissingFieldValidator implements FieldValidator
{

	/**
	 * @throws SecurityTxtSignedButNoCanonicalWarning
	 */
	public function validate(SecurityTxt $securityTxt): void
	{
		if ($securityTxt->getSignatureVerifyResult() && !$securityTxt->getCanonical()) {
			throw new SecurityTxtSignedButNoCanonicalWarning();
		}
	}

}
