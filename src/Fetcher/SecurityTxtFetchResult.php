<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use JsonSerializable;
use Spaze\SecurityTxt\Violations\SecurityTxtSpecViolation;

class SecurityTxtFetchResult implements JsonSerializable
{

	/**
	 * @param array<string, list<string>> $redirects
	 * @param list<SecurityTxtSpecViolation> $errors
	 * @param list<SecurityTxtSpecViolation> $warnings
	 */
	public function __construct(
		private readonly string $constructedUrl,
		private readonly string $finalUrl,
		private readonly array $redirects,
		private readonly string $contents,
		private readonly array $errors,
		private readonly array $warnings,
	) {
	}


	public function getContents(): string
	{
		return $this->contents;
	}


	public function getFinalUrl(): string
	{
		return $this->finalUrl;
	}


	public function getConstructedUrl(): string
	{
		return $this->constructedUrl;
	}


	/**
	 * @return array<string, list<string>>
	 */
	public function getRedirects(): array
	{
		return $this->redirects;
	}


	/**
	 * @return list<SecurityTxtSpecViolation>
	 */
	public function getErrors(): array
	{
		return $this->errors;
	}


	/**
	 * @return list<SecurityTxtSpecViolation>
	 */
	public function getWarnings(): array
	{
		return $this->warnings;
	}


	/**
	 * @return array<string, mixed>
	 */
	public function jsonSerialize(): array
	{
		return [
			'constructedUrl' => $this->getConstructedUrl(),
			'finalUrl' => $this->getFinalUrl(),
			'redirects' => $this->getRedirects(),
			'contents' => $this->getContents(),
			'errors' => $this->getErrors(),
			'warnings' => $this->getWarnings(),
		];
	}

}
