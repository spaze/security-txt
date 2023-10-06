<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher\Exceptions;

use Throwable;

class SecurityTxtNoHttpCodeException extends SecurityTxtFetcherException
{

	/**
	 * @param list<string> $redirects
	 */
	public function __construct(string $url, array $redirects, ?Throwable $previous = null)
	{
		parent::__construct(
			func_get_args(),
			$redirects ? "Missing HTTP code when fetching %s (redirects: %s)" : "Missing HTTP code when fetching %s",
			$redirects ? [$url, implode(' => ', $redirects)] : [$url],
			$url,
			$redirects,
			previous: $previous,
		);
	}

}
