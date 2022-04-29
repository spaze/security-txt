<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Exceptions;

use Throwable;

class SecurityTxtCanonicalNotHttpsError extends SecurityTxtError
{

	public function __construct(?Throwable $previous = null)
	{
		parent::__construct(
			'If the `Canonical` field indicates a web URI, then it must begin with "https://"',
			'draft-foudil-securitytxt-06',
			null,
			'Make sure the `Canonical` field points to an https:// URI',
			'2.5.2',
			previous: $previous,
		);
	}

}
