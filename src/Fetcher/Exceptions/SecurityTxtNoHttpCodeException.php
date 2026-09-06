<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher\Exceptions;

use Throwable;
use Uri\WhatWg\Url;

final class SecurityTxtNoHttpCodeException extends SecurityTxtFetcherException
{

	/**
	 * @param list<string> $redirects
	 */
	public function __construct(Url $url, array $redirects, ?Throwable $previous = null)
	{
		parent::__construct(
			[$url, $redirects],
			'Missing HTTP code when fetching %s' . $this->getRedirectsFormat($redirects),
			[$url, ...$this->redirectValues($redirects)],
			$url,
			$redirects,
			previous: $previous,
		);
	}

}
