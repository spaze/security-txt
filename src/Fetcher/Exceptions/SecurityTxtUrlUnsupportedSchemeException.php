<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher\Exceptions;

use Throwable;

final class SecurityTxtUrlUnsupportedSchemeException extends SecurityTxtFetcherException
{

	/**
	 * @param list<string> $redirects
	 */
	public function __construct(string $url, array $redirects, ?Throwable $previous = null)
	{
		parent::__construct(
			[$url, $redirects],
			'URL %s has an unsupported scheme' . $this->getRedirectsFormat($redirects),
			[$url, ...$redirects],
			$url,
			$redirects,
			previous: $previous,
		);
	}

}
