<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Exceptions;

use Throwable;

class SecurityTxtMultiplePreferredLanguagesError extends SecurityTxtError
{

	public function __construct(?Throwable $previous = null)
	{
		parent::__construct(
			'The `Preferred-Languages` field must not appear more than once',
			'draft-foudil-securitytxt-05',
			null,
			'Make sure the `Preferred-Languages` field is present only once in the file',
			'2.5.8',
			previous: $previous,
		);
	}

}
