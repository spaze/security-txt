<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Exceptions;

use Throwable;

class SecurityTxtContactNotHttpsError extends SecurityTxtError
{

	public function __construct(?Throwable $previous = null)
	{
		parent::__construct(
			'If the `Contact` field indicates a web URI, then it must begin with "https://"',
			'draft-foudil-securitytxt-06',
			null,
			'Make sure the `Contact` field points to an https:// URI',
			'2.5.3',
			previous: $previous,
		);
	}

}
