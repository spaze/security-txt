<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher\Exceptions;

use Throwable;

class SecurityTxtCannotOpenUrlException extends SecurityTxtFetcherException
{

	public function __construct(string $url, ?Throwable $previous = null)
	{
		parent::__construct("Can't open {$url}", $url, previous: $previous);
	}

}
