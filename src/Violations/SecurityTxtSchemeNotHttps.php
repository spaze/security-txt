<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Violations;

class SecurityTxtSchemeNotHttps extends SecurityTxtSpecViolation
{

	public function __construct(string $url)
	{
		parent::__construct(
			"The file at `{$url}` must use HTTPS",
			'draft-foudil-securitytxt-06',
			preg_replace('~^http://~', 'https://', $url),
			'Use HTTPS to serve the `security.txt` file',
			'3',
		);
	}

}
