<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Check;

use Spaze\SecurityTxt\SecurityTxt;
use Spaze\SecurityTxt\Violations\SecurityTxtSpecViolation;

class SecurityTxtCheckHostResult
{

	/**
	 * @param array<string, list<string>> $redirects
	 * @param list<SecurityTxtSpecViolation> $fetchErrors
	 * @param list<SecurityTxtSpecViolation> $fetchWarnings
	 * @param array<int, list<SecurityTxtSpecViolation>> $parseErrors
	 * @param array<int, list<SecurityTxtSpecViolation>> $parseWarnings
	 * @param list<SecurityTxtSpecViolation> $fileErrors
	 * @param list<SecurityTxtSpecViolation> $fileWarnings
	 */
	public function __construct(
		private readonly string $host,
		private readonly ?array $redirects,
		private readonly ?string $constructedUrl,
		private readonly ?string $finalUrl,
		private readonly array $fetchErrors,
		private readonly array $fetchWarnings,
		private readonly array $parseErrors,
		private readonly array $parseWarnings,
		private readonly array $fileErrors,
		private readonly array $fileWarnings,
		private readonly SecurityTxt $securityTxt,
		private readonly bool $expiresSoon,
		private readonly ?bool $isExpired,
		private readonly ?int $expiryDays,
		private readonly bool $isValid,
		private readonly bool $strictMode,
		private readonly ?int $expiresWarningThreshold,
	) {
	}


	public function getHost(): string
	{
		return $this->host;
	}


	/**
	 * @return array<string, list<string>>|null
	 */
	public function getRedirects(): ?array
	{
		return $this->redirects;
	}


	public function getConstructedUrl(): ?string
	{
		return $this->constructedUrl;
	}


	public function getFinalUrl(): ?string
	{
		return $this->finalUrl;
	}


	/**
	 * @return list<SecurityTxtSpecViolation>
	 */
	public function getFetchErrors(): array
	{
		return $this->fetchErrors;
	}


	/**
	 * @return list<SecurityTxtSpecViolation>
	 */
	public function getFetchWarnings(): array
	{
		return $this->fetchWarnings;
	}


	/**
	 * @return array<int, list<SecurityTxtSpecViolation>>
	 */
	public function getParseErrors(): array
	{
		return $this->parseErrors;
	}


	/**
	 * @return array<int, list<SecurityTxtSpecViolation>>
	 */
	public function getParseWarnings(): array
	{
		return $this->parseWarnings;
	}


	/**
	 * @return list<SecurityTxtSpecViolation>
	 */
	public function getFileErrors(): array
	{
		return $this->fileErrors;
	}


	/**
	 * @return list<SecurityTxtSpecViolation>
	 */
	public function getFileWarnings(): array
	{
		return $this->fileWarnings;
	}


	public function getSecurityTxt(): SecurityTxt
	{
		return $this->securityTxt;
	}


	public function isExpiresSoon(): bool
	{
		return $this->expiresSoon;
	}


	public function getIsExpired(): ?bool
	{
		return $this->isExpired;
	}


	public function getExpiryDays(): ?int
	{
		return $this->expiryDays;
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

}
