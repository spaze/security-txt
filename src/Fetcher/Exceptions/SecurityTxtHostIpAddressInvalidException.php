<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher\Exceptions;

use Spaze\SecurityTxt\Fetcher\SecurityTxtIpAddressType;
use Throwable;
use ValueError;

final class SecurityTxtHostIpAddressInvalidException extends SecurityTxtFetcherException
{

	/**
	 * @param SecurityTxtIpAddressType|value-of<SecurityTxtIpAddressType> $ipAddressType An `int` only when rebuilt from JSON, where the wire carries the case value, and any
	 *     other one is refused
	 * @throws ValueError
	 */
	public function __construct(string $host, string $ip, SecurityTxtIpAddressType|int $ipAddressType, string $url, ?Throwable $previous = null)
	{
		$ipAddressType = is_int($ipAddressType) ? SecurityTxtIpAddressType::from($ipAddressType) : $ipAddressType;
		// A `match` rather than an `if`, so a case added later has to be given a name here instead of quietly being called IPv6
		$type = match ($ipAddressType) {
			SecurityTxtIpAddressType::V4 => 'IPv4',
			SecurityTxtIpAddressType::V6 => 'IPv6',
		};
		parent::__construct(
			[$host, $ip, $ipAddressType->value, $url],
			"Host %s resolves to an invalid %s address %s",
			[$host, $type, $ip],
			$url,
			previous: $previous,
		);
	}

}
