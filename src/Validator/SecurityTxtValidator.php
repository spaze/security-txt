<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Validator;

use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtWarning;
use Spaze\SecurityTxt\Fetcher\SecurityTxtFetchResult;
use Spaze\SecurityTxt\SecurityTxt;
use Spaze\SecurityTxt\Validator\Validators\CanonicalUrlValidator;
use Spaze\SecurityTxt\Validator\Validators\ContactMissingFieldValidator;
use Spaze\SecurityTxt\Validator\Validators\ExpiresMissingFieldValidator;
use Spaze\SecurityTxt\Validator\Validators\FieldValidator;
use Spaze\SecurityTxt\Validator\Validators\SignedButCanonicalMissingFieldValidator;

final class SecurityTxtValidator
{

	/**
	 * @var list<FieldValidator>
	 */
	private array $fieldValidators;


	public function __construct()
	{
		$this->fieldValidators = [
			new CanonicalUrlValidator(),
			new ContactMissingFieldValidator(),
			new ExpiresMissingFieldValidator(),
			new SignedButCanonicalMissingFieldValidator(),
		];
	}


	public function validate(SecurityTxt $securityTxt, ?SecurityTxtFetchResult $fetchResult = null): SecurityTxtValidateResult
	{
		$errors = $warnings = [];
		foreach ($this->fieldValidators as $validator) {
			try {
				if ($validator instanceof CanonicalUrlValidator && $fetchResult !== null) {
					$validator->validate($securityTxt, $fetchResult);
				} else {
					$validator->validate($securityTxt);
				}
			} catch (SecurityTxtError $e) {
				$errors[] = $e->getViolation();
			} catch (SecurityTxtWarning $e) {
				$warnings[] = $e->getViolation();
			}
		}
		return new SecurityTxtValidateResult($errors, $warnings);
	}

}
