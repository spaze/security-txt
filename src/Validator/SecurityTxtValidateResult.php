<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Validator;

use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtWarning;

class SecurityTxtValidateResult
{

	/**
	 * @param array<int, SecurityTxtError> $errors
	 * @param array<int, SecurityTxtWarning> $warnings
	 */
	public function __construct(
		private readonly array $errors,
		private readonly array $warnings,
	) {
	}


	/**
	 * @return array<int, SecurityTxtError>
	 */
	public function getErrors(): array
	{
		return $this->errors;
	}


	/**
	 * @return array<int, SecurityTxtWarning>
	 */
	public function getWarnings(): array
	{
		return $this->warnings;
	}

}
