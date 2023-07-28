<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Exceptions;

use Throwable;

class SecurityTxtContentTypeWrongCharsetError extends SecurityTxtError
{

	public function __construct(string $url, string $contentType, ?string $charset, ?Throwable $previous = null)
	{
		parent::__construct(
			"The file at `{$url}` has a correct `Content-Type` of `{$contentType}` but the " . ($charset ? " `{$charset}` parameter should be changed to `charset=utf-8`" : '`charset=utf-8` parameter is missing'),
			'draft-foudil-securitytxt-03',
			'text/plain; charset=utf-8',
			$charset ? 'Change the parameter to `charset=utf-8`' : 'Add a `charset=utf-8` parameter',
			'3',
			previous: $previous,
		);
	}

}
