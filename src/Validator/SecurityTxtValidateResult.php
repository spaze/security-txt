<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Validator;

use Spaze\SecurityTxt\Exceptions\SecurityTxtError;

class SecurityTxtValidateResult
{

	/**
	 * @param array<int, SecurityTxtError> $errors
	 */
	public function __construct(private array $errors)
	{
	}


	/**
	 * @return array<int, SecurityTxtError>
	 */
	public function getErrors(): array
	{
		return $this->errors;
	}

}
