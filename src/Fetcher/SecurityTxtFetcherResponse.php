<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

class SecurityTxtFetcherResponse
{

	/**
	 * @param array<string, string> $headers lowercase name => value
	 */
	public function __construct(
		private readonly int $httpCode,
		private readonly array $headers,
		private readonly string $contents,
	) {
	}


	public function getHttpCode(): int
	{
		return $this->httpCode;
	}


	public function getHeader(string $header): ?string
	{
		return $this->headers[strtolower($header)] ?? null;
	}


	public function getContents(): string
	{
		return $this->contents;
	}

}
