<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher\Exceptions;

use Throwable;

class SecurityTxtNotFoundException extends SecurityTxtFetcherException
{

	/**
	 * @param non-empty-array<string, int> $urls URL => HTTP code
	 * @param Throwable|null $previous
	 */
	public function __construct(array $urls, ?Throwable $previous = null)
	{
		parent::__construct(
			func_get_args(),
			"Can't read security.txt: %s",
			[implode(', ', array_map(fn(string $url, int $code): string => "{$url} => {$code}", array_keys($urls), $urls))],
			array_key_first($urls),
			previous: $previous,
		);
	}

}
