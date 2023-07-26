<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Check;

use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtWarning;
use Spaze\SecurityTxt\SecurityTxt;

class SecurityTxtCheckHostResult
{

	/**
	 * @param array<string, array<int, string>> $redirects
	 * @param array<int, SecurityTxtError> $fetchErrors
	 * @param array<int, SecurityTxtWarning> $fetchWarnings
	 * @param array<int, array<int, SecurityTxtError>> $parseErrors
	 * @param array<int, array<int, SecurityTxtWarning>> $parseWarnings
	 * @param array<int, SecurityTxtError> $fileErrors
	 * @param array<int, SecurityTxtWarning> $fileWarnings
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
	) {
	}


	public function getHost(): string
	{
		return $this->host;
	}


	/**
	 * @return array<string, array<int, string>>|null
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
	 * @return array<int, SecurityTxtError>
	 */
	public function getFetchErrors(): array
	{
		return $this->fetchErrors;
	}


	/**
	 * @return array<int, SecurityTxtWarning>
	 */
	public function getFetchWarnings(): array
	{
		return $this->fetchWarnings;
	}


	/**
	 * @return array<int, array<int, SecurityTxtError>>
	 */
	public function getParseErrors(): array
	{
		return $this->parseErrors;
	}


	/**
	 * @return array<int, array<int, SecurityTxtWarning>>
	 */
	public function getParseWarnings(): array
	{
		return $this->parseWarnings;
	}


	/**
	 * @return array<int, SecurityTxtError>
	 */
	public function getFileErrors(): array
	{
		return $this->fileErrors;
	}


	/**
	 * @return array<int, SecurityTxtWarning>
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

}
