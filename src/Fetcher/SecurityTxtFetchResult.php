<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtWarning;

class SecurityTxtFetchResult
{

	/**
	 * @param array<string, list<string>> $redirects
	 * @param list<SecurityTxtError> $errors
	 * @param list<SecurityTxtWarning> $warnings
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
	 * @return list<SecurityTxtError>
	 */
	public function getErrors(): array
	{
		return $this->errors;
	}


	/**
	 * @return list<SecurityTxtWarning>
	 */
	public function getWarnings(): array
	{
		return $this->warnings;
	}

}
