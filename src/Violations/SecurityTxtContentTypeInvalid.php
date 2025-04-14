<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Violations;

final class SecurityTxtContentTypeInvalid extends SecurityTxtSpecViolation
{

	public function __construct(string $url, ?string $contentType)
	{
		$format = $contentType
			? 'The file at `%s` has a `Content-Type` of `%s` but it should be a `Content-Type` of `text/plain` with the `charset` parameter set to `utf-8`'
			: 'The file at `%s` has no `Content-Type` but it should be a `Content-Type` of `text/plain` with the `charset` parameter set to `utf-8`';
		parent::__construct(
			func_get_args(),
			$format,
			$contentType ? [$url, $contentType] : [$url],
			'draft-foudil-securitytxt-03',
			'text/plain; charset=utf-8',
			'Send a correct `Content-Type` header value of `text/plain` with the `charset` parameter set to `utf-8`',
			[],
			'3',
		);
	}

}
