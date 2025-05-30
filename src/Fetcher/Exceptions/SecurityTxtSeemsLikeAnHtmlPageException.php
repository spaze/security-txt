<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher\Exceptions;

use Throwable;

final class SecurityTxtSeemsLikeAnHtmlPageException extends SecurityTxtFetcherException
{

	/**
	 * @param string $url
	 * @param list<string> $redirects
	 * @param Throwable|null $previous
	 */
	public function __construct(string $url, array $redirects, ?Throwable $previous = null)
	{
		$message = $redirects === []
			? 'The page at %s seems like a regular HTML page, not a %s file'
			: 'When trying to load %s, the request got redirected to what seems like a regular HTML page, not a %s file (redirected to: %s' . str_repeat(' → %s', count($redirects) - 1) . ')';
		parent::__construct(
			[$url, $redirects],
			$message,
			$redirects === [] ? [$url, 'security.txt'] : [$url, 'security.txt', ...$redirects],
			$url,
			$redirects,
			previous: $previous,
		);
	}

}
