<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Violations;

class SecurityTxtContentTypeWrongCharset extends SecurityTxtSpecViolation
{

	public function __construct(string $url, string $contentType, ?string $charset)
	{
		$format = $charset
			? 'The file at `%s` has a correct `Content-Type` of `%s` but the `%s` parameter should be changed to `charset=utf-8`'
			: 'The file at `%s` has a correct `Content-Type` of `%s` but the `charset=utf-8` parameter is missing';
		parent::__construct(
			func_get_args(),
			$format,
			$charset ? [$url, $contentType, $charset] : [$url, $contentType],
			'draft-foudil-securitytxt-03',
			'text/plain; charset=utf-8',
			$charset ? 'Change the parameter to `charset=utf-8`' : 'Add a `charset=utf-8` parameter',
			[],
			'3',
		);
	}

}
