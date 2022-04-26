<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtWarning;

class SecurityTxtFetchResult
{

	/**
	 * @param string $url
	 * @param array<string, array<int, string>> $redirects
	 * @param string $contents
	 * @param array<int, SecurityTxtError> $errors
	 * @param array<int, SecurityTxtWarning> $warnings
	 */
	public function __construct(
		private readonly string $url,
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


	public function getUrl(): string
	{
		return $this->url;
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
