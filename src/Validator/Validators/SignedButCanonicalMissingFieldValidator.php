<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Validator\Validators;

use Spaze\SecurityTxt\Exceptions\SecurityTxtWarning;
use Spaze\SecurityTxt\SecurityTxt;
use Spaze\SecurityTxt\Violations\SecurityTxtSignedButNoCanonical;

class SignedButCanonicalMissingFieldValidator implements FieldValidator
{

	/**
	 * @throws SecurityTxtWarning
	 */
	public function validate(SecurityTxt $securityTxt): void
	{
		if ($securityTxt->getSignatureVerifyResult() && !$securityTxt->getCanonical()) {
			throw new SecurityTxtWarning(new SecurityTxtSignedButNoCanonical());
		}
	}

}
