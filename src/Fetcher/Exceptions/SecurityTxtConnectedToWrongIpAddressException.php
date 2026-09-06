<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher\Exceptions;

use Throwable;
use Uri\WhatWg\Url;

final class SecurityTxtConnectedToWrongIpAddressException extends SecurityTxtFetcherException
{

	/**
	 * @param list<string> $redirects
	 */
	public function __construct(string $expectedIpAddress, string $connectedToIpAddress, Url $url, array $redirects, ?Throwable $previous = null)
	{
		parent::__construct(
			[$expectedIpAddress, $connectedToIpAddress, $url, $redirects],
			"Can't open %s" . $this->getRedirectsFormat($redirects) . ', connected to %s instead of %s as expected',
			[$url, ...$this->redirectValues($redirects), $connectedToIpAddress, $expectedIpAddress],
			$url,
			$redirects,
			previous: $previous,
		);
	}

}
