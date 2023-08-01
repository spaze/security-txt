<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher\Exceptions;

use Spaze\SecurityTxt\Fetcher\SecurityTxtFetcherResponse;
use Throwable;

class SecurityTxtNoLocationHeaderException extends SecurityTxtFetcherException
{

	public function __construct(string $url, SecurityTxtFetcherResponse $response, ?Throwable $previous = null)
	{
		parent::__construct(sprintf('HTTP response with code %d is missing a Location header when fetching %s', $response->getHttpCode(), $url), $url, previous: $previous);
	}

}
