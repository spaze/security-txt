<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtUrlNoSchemeException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtUrlUnsupportedSchemeException;

final readonly class SecurityTxtFetcherUrl
{

	/**
	 * @param list<string> $redirects
	 * @phpstan-param DNS_A|DNS_AAAA $ipAddressType
	 * @psalm-param int $ipAddressType
	 * @throws SecurityTxtUrlNoSchemeException
	 * @throws SecurityTxtUrlUnsupportedSchemeException
	 */
	public function __construct(
		private string $url,
		private array $redirects,
		private string $ipAddress,
		private int $ipAddressType,
	) {
		$scheme = parse_url($this->url, PHP_URL_SCHEME);
		if ($scheme === null || $scheme === false) {
			throw new SecurityTxtUrlNoSchemeException($this->url, $this->redirects);
		}
		if (!in_array(strtolower($scheme), ['http', 'https'], true)) {
			throw new SecurityTxtUrlUnsupportedSchemeException($this->url, $this->redirects);
		}
	}


	public function getUrl(): string
	{
		return $this->url;
	}


	/**
	 * @return list<string>
	 */
	public function getRedirects(): array
	{
		return $this->redirects;
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
