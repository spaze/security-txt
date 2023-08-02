<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser;

use LogicException;
use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtWarning;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtCannotOpenUrlException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtCannotReadUrlException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtHostNotFoundException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtNoHttpCodeException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtNoLocationHeaderException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtNotFoundException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtTooManyRedirectsException;
use Spaze\SecurityTxt\Fetcher\SecurityTxtFetcher;
use Spaze\SecurityTxt\Fields\SecurityTxtField;
use Spaze\SecurityTxt\Parser\LineProcessors\AcknowledgmentsAddFieldValue;
use Spaze\SecurityTxt\Parser\LineProcessors\CanonicalAddFieldValue;
use Spaze\SecurityTxt\Parser\LineProcessors\ContactAddFieldValue;
use Spaze\SecurityTxt\Parser\LineProcessors\EncryptionAddFieldValue;
use Spaze\SecurityTxt\Parser\LineProcessors\ExpiresCheckMultipleFields;
use Spaze\SecurityTxt\Parser\LineProcessors\ExpiresSetFieldValue;
use Spaze\SecurityTxt\Parser\LineProcessors\HiringAddFieldValue;
use Spaze\SecurityTxt\Parser\LineProcessors\LineProcessor;
use Spaze\SecurityTxt\Parser\LineProcessors\PolicyAddFieldValue;
use Spaze\SecurityTxt\Parser\LineProcessors\PreferredLanguagesCheckMultipleFields;
use Spaze\SecurityTxt\Parser\LineProcessors\PreferredLanguagesSetFieldValue;
use Spaze\SecurityTxt\SecurityTxt;
use Spaze\SecurityTxt\Signature\SecurityTxtSignature;
use Spaze\SecurityTxt\Validator\SecurityTxtValidator;
use Spaze\SecurityTxt\Violations\SecurityTxtLineNoEol;
use Spaze\SecurityTxt\Violations\SecurityTxtPossibelFieldTypo;
use Spaze\SecurityTxt\Violations\SecurityTxtSpecViolation;

class SecurityTxtParser
{

	/** @var list<string> */
	private array $lines = [];

	/**
	 * @var array<string, list<LineProcessor>>
	 */
	private array $lineProcessors = [];

	/** @var array<int, list<SecurityTxtSpecViolation>> */
	private array $parseErrors = [];

	/** @var array<int, list<SecurityTxtSpecViolation>> */
	private array $parseWarnings = [];


	public function __construct(
		private readonly SecurityTxtValidator $validator,
		private readonly SecurityTxtSignature $signature,
		private readonly SecurityTxtFetcher $fetcher,
	) {
	}


	private function initLineProcessors(): void
	{
		$this->lineProcessors[SecurityTxtField::Acknowledgments->value] = [
			new AcknowledgmentsAddFieldValue(),
		];
		$this->lineProcessors[SecurityTxtField::Canonical->value] = [
			new CanonicalAddFieldValue(),
		];
		$this->lineProcessors[SecurityTxtField::Contact->value] = [
			new ContactAddFieldValue(),
		];
		$this->lineProcessors[SecurityTxtField::Encryption->value] = [
			new EncryptionAddFieldValue(),
		];
		$this->lineProcessors[SecurityTxtField::Expires->value] = [
			new ExpiresCheckMultipleFields(),
			new ExpiresSetFieldValue(),
		];
		$this->lineProcessors[SecurityTxtField::Hiring->value] = [
			new HiringAddFieldValue(),
		];
		$this->lineProcessors[SecurityTxtField::Policy->value] = [
			new PolicyAddFieldValue(),
		];
		$this->lineProcessors[SecurityTxtField::PreferredLanguages->value] = [
			new PreferredLanguagesCheckMultipleFields(),
			new PreferredLanguagesSetFieldValue(),
		];
	}


	private function processLine(int $lineNumber, string $value, SecurityTxtField $field, SecurityTxt $securityTxt): void
	{
		$this->initLineProcessors();
		foreach ($this->lineProcessors[$field->value] as $processor) {
			try {
				$processor->process($value, $securityTxt);
			} catch (SecurityTxtError $e) {
				$this->parseErrors[$lineNumber][] = $e->getViolation();
			} catch (SecurityTxtWarning $e) {
				$this->parseWarnings[$lineNumber][] = $e->getViolation();
			}
		}
	}


	public function parseString(string $contents, ?int $expiresWarningThreshold = null, bool $strictMode = false): SecurityTxtParseResult
	{
		$this->parseErrors = [];
		$lines = preg_split("/(?<=\n)/", $contents, flags: PREG_SPLIT_NO_EMPTY);
		if (!$lines) {
			throw new LogicException('This should not happen');
		}
		$this->lines = $lines;
		$securityTxtFields = array_combine(
			array_map(function (SecurityTxtField $securityTxtField): string {
				return strtolower($securityTxtField->value);
			}, SecurityTxtField::cases()),
			SecurityTxtField::cases(),
		);
		$securityTxt = new SecurityTxt();
		$securityTxt->allowFieldsWithInvalidValues();
		for ($lineNumber = 1; $lineNumber <= count($this->lines); $lineNumber++) {
			$line = trim($this->lines[$lineNumber - 1]);
			if (!str_ends_with($this->lines[$lineNumber - 1], "\n")) {
				$this->parseErrors[$lineNumber][] = new SecurityTxtLineNoEol($line);
			}
			if (str_starts_with($line, '#')) {
				continue;
			}
			$this->checkSignature($lineNumber, $line, $contents, $securityTxt);
			$field = explode(':', $line, 2);
			if (count($field) !== 2) {
				continue;
			}
			$fieldName = strtolower($field[0]);
			$fieldValue = trim($field[1]);
			if (isset($securityTxtFields[$fieldName])) {
				$this->processLine($lineNumber, $fieldValue, $securityTxtFields[$fieldName], $securityTxt);
			} else {
				$suggestion = $this->getSuggestion($securityTxtFields, $fieldName);
				if ($suggestion) {
					$this->parseWarnings[$lineNumber][] = new SecurityTxtPossibelFieldTypo($field[0], $suggestion, $line);
				}
			}
		}
		$validateResult = $this->validator->validate($securityTxt);
		$expires = $securityTxt->getExpires();
		$expiresSoon = $expiresWarningThreshold !== null && $expires?->inDays() < $expiresWarningThreshold;
		$hasErrors = $this->parseErrors || $validateResult->getErrors();
		$hasWarnings = $this->parseWarnings || $validateResult->getWarnings();
		return new SecurityTxtParseResult(
			$securityTxt,
			!$expires?->isExpired() && (!$strictMode || !$expiresSoon) && !$hasErrors && (!$strictMode || !$hasWarnings),
			$expiresSoon,
			$this->parseErrors,
			$this->parseWarnings,
			$validateResult,
		);
	}


	/**
	 * @throws SecurityTxtCannotOpenUrlException
	 * @throws SecurityTxtCannotReadUrlException
	 * @throws SecurityTxtNotFoundException
	 * @throws SecurityTxtTooManyRedirectsException
	 * @throws SecurityTxtHostNotFoundException
	 * @throws SecurityTxtNoHttpCodeException
	 * @throws SecurityTxtNoLocationHeaderException
	 */
	public function parseHost(string $host, ?int $expiresWarningThreshold = null, bool $strictMode = false, bool $noIpv6 = false): SecurityTxtParseResult
	{
		$fetchResult = $this->fetcher->fetchHost($host, $noIpv6);
		$parseResult = $this->parseString($fetchResult->getContents(), $expiresWarningThreshold, $strictMode);
		return new SecurityTxtParseResult(
			$parseResult->getSecurityTxt(),
			$parseResult->isValid() && !$fetchResult->getErrors() && (!$strictMode || !$fetchResult->getWarnings()),
			$parseResult->isExpiresSoon(),
			$parseResult->getParseErrors(),
			$parseResult->getParseWarnings(),
			$parseResult->getValidateResult(),
			$fetchResult,
		);
	}


	private function checkSignature(int $lineNumber, string $line, string $contents, SecurityTxt $securityTxt): void
	{
		if ($this->signature->isCleartextHeader($line)) {
			try {
				$result = $this->signature->verify($contents);
				$securityTxt->setSignatureVerifyResult($result);
			} catch (SecurityTxtError $e) {
				$this->parseErrors[$lineNumber][] = $e->getViolation();
			} catch (SecurityTxtWarning $e) {
				$this->parseWarnings[$lineNumber][] = $e->getViolation();
			}
		}
	}


	public function getLine(int $lineNumber): ?string
	{
		return $this->lines[$lineNumber] ?? null;
	}


	/**
	 * @see https://github.com/nette/utils/blob/c7ec4476eff478e6eec4263171ae0e3b0e2b4e55/src/Utils/Helpers.php#L72 Algorithm taken from nette/utils under the terms of the New BSD License
	 * @param array<string, SecurityTxtField> $securityTxtFields
	 */
	public function getSuggestion(array $securityTxtFields, string $lowercaseName): ?SecurityTxtField
	{
		$best = null;
		$min = (strlen($lowercaseName) / 4 + 1) * 10 + .1;
		foreach ($securityTxtFields as $lowercaseSecurityTxtFieldName => $securityTxtField) {
			$len = levenshtein($lowercaseSecurityTxtFieldName, $lowercaseName, 10, 11, 10);
			if ($lowercaseSecurityTxtFieldName !== $lowercaseName && $len < $min) {
				$min = $len;
				$best = $securityTxtField;
			}
		}
		return $best;
	}

}
