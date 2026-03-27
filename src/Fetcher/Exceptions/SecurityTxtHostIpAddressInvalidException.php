<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher\Exceptions;

use Throwable;

final class SecurityTxtHostIpAddressInvalidException extends SecurityTxtFetcherException
{

	/**
	 * @phpstan-param DNS_A|DNS_AAAA $ipAddressType
	 * @psalm-param int $ipAddressType
	 */
	public function __construct(string $host, string $ip, int $ipAddressType, string $url, ?Throwable $previous = null)
	{
		if ($ipAddressType === DNS_A) {
			$type = 'IPv4';
		} else {
			$type = 'IPv6';
		}
		parent::__construct(
			[$host, $ip, $ipAddressType, $url],
			"Host %s resolves to an invalid %s address %s",
			[$host, $type, $ip],
			$url,
			previous: $previous,
		);
	}

}
