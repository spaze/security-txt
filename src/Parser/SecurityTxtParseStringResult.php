<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser;

use JsonSerializable;
use Override;
use Spaze\SecurityTxt\SecurityTxt;
use Spaze\SecurityTxt\Validator\SecurityTxtValidateResult;
use Spaze\SecurityTxt\Violations\SecurityTxtSpecViolation;

final readonly class SecurityTxtParseStringResult implements JsonSerializable
{

	/**
	 * @param array<int, list<SecurityTxtSpecViolation>> $lineErrors
	 * @param array<int, list<SecurityTxtSpecViolation>> $lineWarnings
	 */
	public function __construct(
		private SecurityTxt $securityTxt,
		private bool $isValid,
		private bool $strictMode,
		private ?int $expiresWarningThreshold,
		private bool $expiresSoon,
		private array $lineErrors,
		private array $lineWarnings,
		private SecurityTxtValidateResult $validateResult,
	) {
	}


	public function getSecurityTxt(): SecurityTxt
	{
		return $this->securityTxt;
	}


	public function isValid(): bool
	{
		return $this->isValid;
	}


	public function isStrictMode(): bool
	{
		return $this->strictMode;
	}


	public function getExpiresWarningThreshold(): ?int
	{
		return $this->expiresWarningThreshold;
	}


	public function isExpiresSoon(): bool
	{
		return $this->expiresSoon;
	}


	/**
	 * @return array<int, list<SecurityTxtSpecViolation>>
	 */
	public function getLineErrors(): array
	{
		return $this->lineErrors;
	}


	/**
	 * @return list<SecurityTxtSpecViolation>
	 */
	public function getFileErrors(): array
	{
		return $this->validateResult->getErrors();
	}


	public function hasErrors(): bool
	{
		return $this->getLineErrors() !== [] || $this->getFileErrors() !== [];
	}


	/**
	 * @return array<int, list<SecurityTxtSpecViolation>>
	 */
	public function getLineWarnings(): array
	{
		return $this->lineWarnings;
	}


	/**
	 * @return list<SecurityTxtSpecViolation>
	 */
	public function getFileWarnings(): array
	{
		return $this->validateResult->getWarnings();
	}


	public function hasWarnings(): bool
	{
		return $this->getLineWarnings() !== [] || $this->getFileWarnings() !== [];
	}


	public function getValidateResult(): SecurityTxtValidateResult
	{
		return $this->validateResult;
	}


	/**
	 * @return array<string, mixed>
	 */
	#[Override]
	public function jsonSerialize(): array
	{
		return [
			'securityTxt' => $this->getSecurityTxt(),
			'isValid' => $this->isValid(),
			'strictMode' => $this->isStrictMode(),
			'expiresWarningThreshold' => $this->getExpiresWarningThreshold(),
			'expiresSoon' => $this->isExpiresSoon(),
			'lineErrors' => $this->getLineErrors(),
			'lineWarnings' => $this->getLineWarnings(),
			'validateResult' => $this->getValidateResult(),
		];
	}

}
