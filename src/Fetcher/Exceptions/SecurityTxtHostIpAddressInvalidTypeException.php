<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher\Exceptions;

use Throwable;

class SecurityTxtHostIpAddressInvalidTypeException extends SecurityTxtFetcherException
{

	public function __construct(string $host, string $type, string $url, ?Throwable $previous = null)
	{
		parent::__construct(func_get_args(), "IP address of %s is a %s, should be a string", [$host, $type], $url, previous: $previous);
	}

}
