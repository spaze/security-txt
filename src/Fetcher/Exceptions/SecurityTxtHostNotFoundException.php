<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher\Exceptions;

use Spaze\SecurityTxt\SecurityTxtHost;
use Throwable;

final class SecurityTxtHostNotFoundException extends SecurityTxtFetcherException
{

	public function __construct(string $url, SecurityTxtHost $host, ?Throwable $previous = null)
	{
		// The params stay scalar so a replay can rebuild this from JSON, the values carry the host itself so it prints as it reads
		parent::__construct([$url, $host->getUnicode()], "Can't open %s, can't resolve %s", [$url, $host], $url, previous: $previous);
	}

}
