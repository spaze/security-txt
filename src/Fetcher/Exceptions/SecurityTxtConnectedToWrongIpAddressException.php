<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher\Exceptions;

use Throwable;

final class SecurityTxtConnectedToWrongIpAddressException extends SecurityTxtFetcherException
{

	/**
	 * @param list<string> $redirects
	 */
	public function __construct(string $expectedIpAddress, string $connectedToIpAddress, string $url, array $redirects, ?Throwable $previous = null)
	{
		parent::__construct(
			[$expectedIpAddress, $connectedToIpAddress, $url, $redirects],
			"Can't open %s" . $this->getRedirectsFormat($redirects) . ', connected to %s instead of %s as expected',
			[$url, ...$redirects, $connectedToIpAddress, $expectedIpAddress],
			$url,
			$redirects,
			previous: $previous,
		);
	}

}
