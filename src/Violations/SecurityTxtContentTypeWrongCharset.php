<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Violations;

use Spaze\SecurityTxt\SecurityTxtContentType;

final class SecurityTxtContentTypeWrongCharset extends SecurityTxtSpecViolation
{

	public function __construct(string $uri, string $contentType, ?string $charset)
	{
		$format = $charset !== null
			? 'The file at %s has a correct %s of %s but the %s parameter should be changed to %s'
			: 'The file at %s has a correct %s of %s but the %s parameter is missing';
		parent::__construct(
			func_get_args(),
			$format,
			$charset !== null ? [$uri, 'Content-Type', $contentType, $charset, SecurityTxtContentType::CHARSET_PARAMETER] : [$uri, 'Content-Type', $contentType, SecurityTxtContentType::CHARSET_PARAMETER],
			'draft-foudil-securitytxt-03',
			SecurityTxtContentType::MEDIA_TYPE,
			$charset !== null ? 'Change the parameter to %s' : 'Add a %s parameter',
			[SecurityTxtContentType::CHARSET_PARAMETER],
			'3',
		);
	}

}
