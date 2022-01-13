<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Validator;

use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\SecurityTxt;
use Spaze\SecurityTxt\Validator\Validators\ExpiresMissingFieldValidator;
use Spaze\SecurityTxt\Validator\Validators\FieldValidator;

class SecurityTxtValidator
{

	/**
	 * @var array<int, FieldValidator>
	 */
	private array $fieldValidators;


	public function __construct()
	{
		$this->fieldValidators = [
			new ExpiresMissingFieldValidator(),
		];
	}


	public function validate(SecurityTxt $securityTxt): SecurityTxtValidateResult
	{
		$errors = [];
		foreach ($this->fieldValidators as $validator) {
			try {
				$validator->validate($securityTxt);
			} catch (SecurityTxtError $e) {
				$errors[] = $e;
			}
		}
		return new SecurityTxtValidateResult($errors);
	}

}
