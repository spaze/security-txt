<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher\Exceptions;

use Throwable;

class SecurityTxtCannotParseHostnameException extends SecurityTxtFetcherException
{

	public function __construct(string $url, ?Throwable $previous = null)
	{
		parent::__construct(func_get_args(), "Can't parse hostname from %s", [$url], $url, previous: $previous);
	}

}
