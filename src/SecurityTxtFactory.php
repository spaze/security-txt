<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt;

use DateTimeImmutable;
use Exception;
use Spaze\SecurityTxt\Check\Exceptions\SecurityTxtCannotParseJsonException;
use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtWarning;
use Spaze\SecurityTxt\Fields\Acknowledgments;
use Spaze\SecurityTxt\Fields\Canonical;
use Spaze\SecurityTxt\Fields\Contact;
use Spaze\SecurityTxt\Fields\Encryption;
use Spaze\SecurityTxt\Fields\Expires;
use Spaze\SecurityTxt\Fields\Hiring;
use Spaze\SecurityTxt\Fields\Policy;
use Spaze\SecurityTxt\Fields\PreferredLanguages;
use Spaze\SecurityTxt\Fields\SecurityTxtUriField;
use Spaze\SecurityTxt\Signature\SecurityTxtSignatureVerifyResult;

class SecurityTxtFactory
{

	/**
	 * @param array<string, mixed> $values
	 * @return SecurityTxt
	 * @throws SecurityTxtCannotParseJsonException
	 */
	public function createFromJsonValues(array $values): SecurityTxt
	{
		$securityTxt = new SecurityTxt(SecurityTxtValidationLevel::AllowInvalidValuesSilently);
		try {
			if ($values['expires']) {
				if (!is_array($values['expires'])) {
					throw new SecurityTxtCannotParseJsonException('expires is not an array');
				} elseif (!isset($values['expires']['dateTime']) || !is_string($values['expires']['dateTime'])) {
					throw new SecurityTxtCannotParseJsonException('expires > dateTime is missing or not a string');
				}
				try {
					$dateTime = new DateTimeImmutable($values['expires']['dateTime']);
				} catch (Exception $e) {
					throw new SecurityTxtCannotParseJsonException('expires > dateTime is wrong format', $e);
				}
				$securityTxt->setExpires(new Expires($dateTime));
			}
			if ($values['signatureVerifyResult']) {
				if (!is_array($values['signatureVerifyResult'])) {
					throw new SecurityTxtCannotParseJsonException('signatureVerifyResult is not an array');
				} elseif (
					!isset($values['signatureVerifyResult']['keyFingerprint'])
					|| !is_string($values['signatureVerifyResult']['keyFingerprint'])
				) {
					throw new SecurityTxtCannotParseJsonException('signatureVerifyResult > keyFingerprint is missing or not a string');
				} elseif (
					!isset($values['signatureVerifyResult']['dateTime'])
					|| !is_string($values['signatureVerifyResult']['dateTime'])
				) {
					throw new SecurityTxtCannotParseJsonException('signatureVerifyResult > dateTime is missing or not a string');
				}
				try {
					$dateTime = new DateTimeImmutable($values['signatureVerifyResult']['dateTime']);
				} catch (Exception $e) {
					throw new SecurityTxtCannotParseJsonException('signatureVerifyResult > dateTime is wrong format', $e);
				}
				$securityTxt->setSignatureVerifyResult(new SecurityTxtSignatureVerifyResult($values['signatureVerifyResult']['keyFingerprint'], $dateTime));
			}
			if ($values['preferredLanguages']) {
				if (!is_array($values['preferredLanguages'])) {
					throw new SecurityTxtCannotParseJsonException('preferredLanguages is not an array');
				} elseif (
					!isset($values['preferredLanguages']['languages'])
					|| !is_array($values['preferredLanguages']['languages'])
				) {
					throw new SecurityTxtCannotParseJsonException('preferredLanguages > languages is missing or not an array');
				}
				$languages = [];
				foreach ($values['preferredLanguages']['languages'] as $language) {
					if (!is_string($language)) {
						throw new SecurityTxtCannotParseJsonException('preferredLanguages > languages contains an item which is not a string');
					}
					$languages[] = $language;
				}
				$securityTxt->setPreferredLanguages(new PreferredLanguages($languages));
			}
			$this->addSecurityTxtUriField($values, 'canonical', Canonical::class, $securityTxt->addCanonical(...));
			$this->addSecurityTxtUriField($values, 'contact', Contact::class, $securityTxt->addContact(...));
			$this->addSecurityTxtUriField($values, 'acknowledgments', Acknowledgments::class, $securityTxt->addAcknowledgments(...));
			$this->addSecurityTxtUriField($values, 'hiring', Hiring::class, $securityTxt->addHiring(...));
			$this->addSecurityTxtUriField($values, 'policy', Policy::class, $securityTxt->addPolicy(...));
			$this->addSecurityTxtUriField($values, 'encryption', Encryption::class, $securityTxt->addEncryption(...));
		} catch (SecurityTxtError | SecurityTxtWarning $e) {
			throw new SecurityTxtCannotParseJsonException($e->getMessage(), $e);
		}
		return $securityTxt;
	}


	/**
	 * @template T of SecurityTxtUriField
	 * @param array<array-key, mixed> $values
	 * @param callable(T): void $addField
	 * @param class-string<T> $class
	 * @throws SecurityTxtCannotParseJsonException
	 */
	private function addSecurityTxtUriField(array $values, string $field, string $class, callable $addField): void
	{
		if (!is_array($values[$field])) {
			throw new SecurityTxtCannotParseJsonException("Field {$field} is not an array");
		}
		foreach ($values[$field] as $value) {
			if (!is_array($value)) {
				throw new SecurityTxtCannotParseJsonException("{$field} is not an array");
			} elseif (!isset($value['uri']) || !is_string($value['uri'])) {
				throw new SecurityTxtCannotParseJsonException("{$field} > uri is missing or not a string");
			}
			$addField(new $class($value['uri']));
		}
	}

}
