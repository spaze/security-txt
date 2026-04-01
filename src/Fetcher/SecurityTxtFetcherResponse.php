<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

final readonly class SecurityTxtFetcherResponse
{

	/**
	 * @param array<lowercase-string, string> $headers lowercase name => value
	 * @phpstan-param DNS_A|DNS_AAAA $ipAddressType
	 * @psalm-param int $ipAddressType
	 */
	public function __construct(
		private int $httpCode,
		private array $headers,
		private string $contents,
		private bool $isTruncated,
		private string $ipAddress,
		private int $ipAddressType,
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


	public function isTruncated(): bool
	{
		return $this->isTruncated;
	}


	public function getIpAddress(): string
	{
		return $this->ipAddress;
	}


	/**
	 * @phpstan-return DNS_A|DNS_AAAA
	 * @psalm-return int
	 */
	public function getIpAddressType(): int
	{
		return $this->ipAddressType;
	}

}
