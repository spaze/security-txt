<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Exceptions;

use Throwable;

class SecurityTxtPreferredLanguagesEmptyError extends SecurityTxtError
{

	public function __construct(?Throwable $previous = null)
	{
		parent::__construct(
			'The `Preferred-Languages` field must have at least one language listed',
			'draft-foudil-securitytxt-05',
			null,
			'Add one or more languages to the field, separated by commas',
			'2.5.8',
			previous: $previous,
		);
	}

}
