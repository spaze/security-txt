<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher\Exceptions;

use Spaze\SecurityTxt\Fetcher\SecurityTxtFetcherUrl;
use Throwable;

class SecurityTxtCannotReadUrlException extends SecurityTxtFetcherException
{

	public function __construct(SecurityTxtFetcherUrl $url, ?Throwable $previous = null)
	{
		parent::__construct(
			func_get_args(),
			$url->getRedirects() ? "Can't get contents of %s (redirects: %s)" : "Can't get contents of %s",
			$url->getRedirects() ? [$url->getUrl(), implode(' => ', $url->getRedirects())] : [$url->getUrl()],
			$url->getUrl(),
			$url->getRedirects(),
			previous: $previous,
		);
	}

}
