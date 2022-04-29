<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Exceptions;

use Throwable;

class SecurityTxtMultipleExpiresError extends SecurityTxtError
{

	public function __construct(?Throwable $previous = null)
	{
		parent::__construct(
			'The `Expires` field must not appear more than once',
			'draft-foudil-securitytxt-09',
			null,
			'Make sure the `Expires` field is present only once in the file',
			'2.5.5',
			previous: $previous,
		);
	}

}
