<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher\Exceptions;

use Throwable;

class SecurityTxtHostNotFoundException extends SecurityTxtFetcherException
{

	public function __construct(string $url, string $host, ?Throwable $previous = null)
	{
		parent::__construct("Can't open {$url}, can't resolve {$host}", $url, previous: $previous);
	}

}
