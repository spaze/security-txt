<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher\Exceptions;

use Spaze\SecurityTxt\SecurityTxtHost;
use Throwable;

final class SecurityTxtHostIpAddressNotPublicException extends SecurityTxtFetcherException
{

	public function __construct(SecurityTxtHost $host, string $ip, string $url, ?Throwable $previous = null)
	{
		// The params stay scalar so a replay can rebuild this from JSON, the values carry the host itself so it prints as it reads
		parent::__construct(
			[$host->getUnicode(), $ip, $url],
			"Host %s resolves to a non-public IP address %s",
			[$host, $ip],
			$url,
			previous: $previous,
		);
	}

}
