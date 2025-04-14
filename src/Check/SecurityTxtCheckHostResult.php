<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Check;

use JsonSerializable;
use Override;
use Spaze\SecurityTxt\Fetcher\SecurityTxtFetchResult;
use Spaze\SecurityTxt\SecurityTxt;
use Spaze\SecurityTxt\Violations\SecurityTxtSpecViolation;

readonly class SecurityTxtCheckHostResult implements JsonSerializable
{

	/**
	 * @param array<string, list<string>> $redirects
	 * @param list<SecurityTxtSpecViolation> $fetchErrors
	 * @param list<SecurityTxtSpecViolation> $fetchWarnings
	 * @param array<int, list<SecurityTxtSpecViolation>> $lineErrors
	 * @param array<int, list<SecurityTxtSpecViolation>> $lineWarnings
	 * @param list<SecurityTxtSpecViolation> $fileErrors
	 * @param list<SecurityTxtSpecViolation> $fileWarnings
	 */
	public function __construct(
		private string $host,
		private ?array $redirects,
		private ?string $constructedUrl,
		private ?string $finalUrl,
		private ?string $contents,
		private ?SecurityTxtFetchResult $fetchResult,
		private array $fetchErrors,
		private array $fetchWarnings,
		private array $lineErrors,
		private array $lineWarnings,
		private array $fileErrors,
		private array $fileWarnings,
		private SecurityTxt $securityTxt,
		private bool $expiresSoon,
		private ?bool $isExpired,
		private ?int $expiryDays,
		private bool $isValid,
		private bool $strictMode,
		private ?int $expiresWarningThreshold,
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


	public function getContents(): ?string
	{
		return $this->contents;
	}


	public function getFetchResult(): ?SecurityTxtFetchResult
	{
		return $this->fetchResult;
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
	public function getLineErrors(): array
	{
		return $this->lineErrors;
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


	/**
	 * @return array<string, mixed>
	 */
	#[Override]
	public function jsonSerialize(): array
	{
		return [
			'class' => $this::class,
			'host' => $this->getHost(),
			'redirects' => $this->getRedirects(),
			'constructedUrl' => $this->getConstructedUrl(),
			'finalUrl' => $this->getFinalUrl(),
			'contents' => $this->getContents(),
			'fetchResult' => $this->getFetchResult(),
			'fetchErrors' => $this->getFetchErrors(),
			'fetchWarnings' => $this->getFetchWarnings(),
			'lineErrors' => $this->getLineErrors(),
			'lineWarnings' => $this->getLineWarnings(),
			'fileErrors' => $this->getFileErrors(),
			'fileWarnings' => $this->getFileWarnings(),
			'securityTxt' => $this->getSecurityTxt(),
			'expiresSoon' => $this->isExpiresSoon(),
			'expired' => $this->getIsExpired(),
			'expiryDays' => $this->getExpiryDays(),
			'valid' => $this->isValid(),
			'strictMode' => $this->isStrictMode(),
			'expiresWarningThreshold' => $this->getExpiresWarningThreshold(),
		];
	}

}
