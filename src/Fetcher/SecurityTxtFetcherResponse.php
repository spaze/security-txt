<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use JsonSerializable;

class SecurityTxtFetcherResponse implements JsonSerializable
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


	/**
	 * @return array<string, string>
	 */
	public function getHeaders(): array
	{
		return $this->headers;
	}


	public function getHeader(string $header): ?string
	{
		return $this->headers[strtolower($header)] ?? null;
	}


	public function getContents(): string
	{
		return $this->contents;
	}


	/**
	 * @return array<string, mixed>
	 */
	public function jsonSerialize(): array
	{
		return [
			'httpCode' => $this->getHttpCode(),
			'headers' => $this->getHeaders(),
			'contents' => $this->getContents(),
		];
	}

}
