<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtWarning;

class SecurityTxtFetchResult
{

	/**
	 * @param array<string, array<int, string>> $redirects
	 * @param array<int, SecurityTxtError> $errors
	 * @param array<int, SecurityTxtWarning> $warnings
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
	 * @return array<string, array<int, string>>
	 */
	public function getRedirects(): array
	{
		return $this->redirects;
	}


	/**
	 * @return array<int, SecurityTxtError>
	 */
	public function getErrors(): array
	{
		return $this->errors;
	}


	/**
	 * @return array<int, SecurityTxtWarning>
	 */
	public function getWarnings(): array
	{
		return $this->warnings;
	}

}
