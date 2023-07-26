<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Validator;

use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtWarning;

class SecurityTxtValidateResult
{

	/**
	 * @param list<SecurityTxtError> $errors
	 * @param list<SecurityTxtWarning> $warnings
	 */
	public function __construct(
		private readonly array $errors,
		private readonly array $warnings,
	) {
	}


	/**
	 * @return list<SecurityTxtError>
	 */
	public function getErrors(): array
	{
		return $this->errors;
	}


	/**
	 * @return list<SecurityTxtWarning>
	 */
	public function getWarnings(): array
	{
		return $this->warnings;
	}

}
