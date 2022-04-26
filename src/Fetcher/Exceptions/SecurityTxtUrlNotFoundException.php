<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher\Exceptions;

use Throwable;

class SecurityTxtUrlNotFoundException extends SecurityTxtFetcherException
{

	public function __construct(string $url, int $code, ?Throwable $previous = null)
	{
		parent::__construct(sprintf('URL %s not found, code %d', $url, $code), $url, $code, $previous);
	}

}
