<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher\Exceptions;

use Throwable;

class SecurityTxtNoHttpCodeException extends SecurityTxtFetcherException
{

	public function __construct(string $url, ?Throwable $previous = null)
	{
		parent::__construct("Missing HTTP code when fetching {$url}", $url, previous: $previous);
	}

}
