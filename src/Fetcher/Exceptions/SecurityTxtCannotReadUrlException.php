<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher\Exceptions;

use Throwable;

class SecurityTxtCannotReadUrlException extends SecurityTxtFetcherException
{

	/**
	 * @param list<string> $redirects
	 */
	public function __construct(string $url, array $redirects, ?Throwable $previous = null)
	{
		parent::__construct(
			func_get_args(),
			$redirects ? "Can't get contents of %s (redirects: %s)" : "Can't get contents of %s",
			$redirects ? [$url, implode(' => ', $redirects)] : [$url],
			$url,
			$redirects,
			previous: $previous,
		);
	}

}
