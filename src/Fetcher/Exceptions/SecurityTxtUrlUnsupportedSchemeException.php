<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher\Exceptions;

use Throwable;
use Uri\WhatWg\Url;

final class SecurityTxtUrlUnsupportedSchemeException extends SecurityTxtFetcherException
{

	/**
	 * @param list<string> $redirects
	 */
	public function __construct(Url $url, array $redirects, ?Throwable $previous = null)
	{
		parent::__construct(
			[$url, $redirects],
			'URL %s has an unsupported scheme' . $this->getRedirectsFormat($redirects),
			[$url, ...$this->redirectValues($redirects)],
			$url,
			$redirects,
			previous: $previous,
		);
	}

}
