<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser;

use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtWarning;
use Spaze\SecurityTxt\Fetcher\SecurityTxtFetchResult;
use Spaze\SecurityTxt\SecurityTxt;
use Spaze\SecurityTxt\Validator\SecurityTxtValidateResult;

class SecurityTxtParseResult
{

	/**
	 * @param SecurityTxt $securityTxt
	 * @param array<int, list<SecurityTxtError>> $parseErrors
	 * @param array<int, list<SecurityTxtWarning>> $parseWarnings
	 * @param SecurityTxtValidateResult $validateResult
	 * @param SecurityTxtFetchResult|null $fetchResult
	 */
	public function __construct(
		private readonly SecurityTxt $securityTxt,
		private readonly array $parseErrors,
		private readonly array $parseWarnings,
		private readonly SecurityTxtValidateResult $validateResult,
		private readonly ?SecurityTxtFetchResult $fetchResult = null,
	) {
	}


	public function getSecurityTxt(): SecurityTxt
	{
		return $this->securityTxt;
	}


	/**
	 * @return list<SecurityTxtError>
	 */
	public function getFetchErrors(): array
	{
		return $this->fetchResult ? $this->fetchResult->getErrors() : [];
	}


	/**
	 * @return array<int, list<SecurityTxtError>>
	 */
	public function getParseErrors(): array
	{
		return $this->parseErrors;
	}


	/**
	 * @return list<SecurityTxtError>
	 */
	public function getFileErrors(): array
	{
		return $this->validateResult->getErrors();
	}


	public function hasErrors(): bool
	{
		return $this->getFetchErrors() || $this->getParseErrors() || $this->getFileErrors();
	}


	/**
	 * @return list<SecurityTxtWarning>
	 */
	public function getFetchWarnings(): array
	{
		return $this->fetchResult ? $this->fetchResult->getWarnings() : [];
	}


	/**
	 * @return array<int, list<SecurityTxtWarning>>
	 */
	public function getParseWarnings(): array
	{
		return $this->parseWarnings;
	}


	/**
	 * @return list<SecurityTxtWarning>
	 */
	public function getFileWarnings(): array
	{
		return $this->validateResult->getWarnings();
	}


	public function hasWarnings(): bool
	{
		return $this->getFetchWarnings() || $this->getParseWarnings() || $this->getFileWarnings();
	}


	public function getFetchResult(): ?SecurityTxtFetchResult
	{
		return $this->fetchResult;
	}


	public function getValidateResult(): SecurityTxtValidateResult
	{
		return $this->validateResult;
	}

}
