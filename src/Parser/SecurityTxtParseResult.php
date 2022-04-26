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
	 * @param array<int, array<int, SecurityTxtError>> $parseErrors
	 * @param array<int, array<int, SecurityTxtWarning>> $parseWarnings
	 * @param SecurityTxtValidateResult $validateResult
	 * @param SecurityTxtFetchResult|null $fetchResult
	 */
	public function __construct(
		private SecurityTxt $securityTxt,
		private array $parseErrors,
		private array $parseWarnings,
		private SecurityTxtValidateResult $validateResult,
		private readonly ?SecurityTxtFetchResult $fetchResult = null,
	) {
	}


	public static function fromResults(
		self $parseResult,
		SecurityTxtFetchResult $fetchResult,
	): self {
		return new self(
			$parseResult->getSecurityTxt(),
			$parseResult->getParseErrors(),
			$parseResult->getParseWarnings(),
			$parseResult->getValidateResult(),
			$fetchResult,
		);
	}


	public function getSecurityTxt(): SecurityTxt
	{
		return $this->securityTxt;
	}


	/**
	 * @return array<int, SecurityTxtError>
	 */
	public function getFetchErrors(): array
	{
		return $this->fetchResult ? $this->fetchResult->getErrors() : [];
	}


	/**
	 * @return array<int, array<int, SecurityTxtError>>
	 */
	public function getParseErrors(): array
	{
		return $this->parseErrors;
	}


	/**
	 * @return array<int, SecurityTxtError>
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
	 * @return array<int, SecurityTxtWarning>
	 */
	public function getFetchWarnings(): array
	{
		return $this->fetchResult ? $this->fetchResult->getWarnings() : [];
	}


	/**
	 * @return array<int, array<int, SecurityTxtWarning>>
	 */
	public function getParseWarnings(): array
	{
		return $this->parseWarnings;
	}


	/**
	 * @return array<int, SecurityTxtWarning>
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
