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

	private CanonicalUrlValidator $canonicalUrlValidator;


	public function __construct()
	{
		$this->fieldValidators = [
			new ContactMissingFieldValidator(),
			new ExpiresMissingFieldValidator(),
			new SignedButCanonicalMissingFieldValidator(),
		];
		$this->canonicalUrlValidator = new CanonicalUrlValidator();
	}


	public function validate(SecurityTxt $securityTxt): SecurityTxtValidateResult
	{
		$errors = $warnings = [];
		foreach ($this->fieldValidators as $validator) {
			try {
				$validator->validate($securityTxt);
			} catch (SecurityTxtError $e) {
				$errors[] = $e->getViolation();
			} catch (SecurityTxtWarning $e) {
				$warnings[] = $e->getViolation();
			}
		}
		return new SecurityTxtValidateResult($errors, $warnings);
	}


	public function validateWithFetchResult(SecurityTxt $securityTxt, SecurityTxtFetchResult $fetchResult): SecurityTxtValidateResult
	{
		$result = $this->validate($securityTxt);
		try {
			$this->canonicalUrlValidator->validate($securityTxt, $fetchResult);
		} catch (SecurityTxtError $e) {
			return new SecurityTxtValidateResult(
				array_merge($result->getErrors(), [$e->getViolation()]),
				$result->getWarnings(),
			);
		} catch (SecurityTxtWarning $e) {
			return new SecurityTxtValidateResult(
				$result->getErrors(),
				array_merge($result->getWarnings(), [$e->getViolation()]),
			);
		}
		return $result;
	}

}
