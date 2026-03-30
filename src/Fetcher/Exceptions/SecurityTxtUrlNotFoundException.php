<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher\Exceptions;

use Throwable;

final class SecurityTxtUrlNotFoundException extends SecurityTxtFetcherException
{

	/**
	 * @phpstan-param DNS_A|DNS_AAAA $ipAddressType
	 * @psalm-param int $ipAddressType
	 */
	public function __construct(
		string $url,
		int $code,
		private readonly string $ipAddress,
		private readonly int $ipAddressType,
		?Throwable $previous = null,
	) {
		parent::__construct([$url, $code, $ipAddress, $ipAddressType], 'URL %s not found, code %s', [$url, (string)$code], $url, code: $code, previous: $previous);
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
