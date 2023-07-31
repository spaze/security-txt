<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Exceptions;

use Throwable;

class SecurityTxtSchemeNotHttpsError extends SecurityTxtError
{

	public function __construct(string $url, ?Throwable $previous = null)
	{
		parent::__construct(
			"The file at `{$url}` must use HTTPS",
			'draft-foudil-securitytxt-06',
			preg_replace('~^http://~', 'https://', $url),
			'Use HTTPS to serve the `security.txt` file',
			'3',
			previous: $previous,
		);
	}

}
