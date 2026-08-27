<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher\Exceptions;

use Spaze\SecurityTxt\SecurityTxtHost;
use Throwable;

final class SecurityTxtOnlyIpv6HostButIpv6DisabledException extends SecurityTxtFetcherException
{

	public function __construct(string|SecurityTxtHost $host, string $ipv6, string $url, ?Throwable $previous = null)
	{
		// The params stay scalar so a replay can rebuild this from JSON, the values carry the host itself so it prints as it reads
		$host = self::toHost($host);
		parent::__construct([self::hostToString($host), $ipv6, $url], 'Only IPv6 host is available (%s, %s) but IPv6 is disabled', [$host, $ipv6], $url, previous: $previous);
	}

}
