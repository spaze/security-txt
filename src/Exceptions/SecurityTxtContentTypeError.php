<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Exceptions;

use Throwable;

class SecurityTxtContentTypeError extends SecurityTxtError
{

	public function __construct(string $url, ?string $contentType, ?Throwable $previous = null)
	{
		parent::__construct(
			"The file at `{$url}` has " . ($contentType ? "a `Content-Type` of `{$contentType}`" : 'no `Content-Type`') . " but it should be a `Content-Type` of `text/plain` with the `charset` parameter set to `utf-8`",
			'draft-foudil-securitytxt-03',
			'text/plain; charset=utf-8',
			'Send a correct `Content-Type` header value of `text/plain` with the `charset` parameter set to `utf-8`',
			'3',
			previous: $previous,
		);
	}

}
