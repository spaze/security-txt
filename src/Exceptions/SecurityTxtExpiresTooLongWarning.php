<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Exceptions;

use DateTimeImmutable;
use Throwable;

class SecurityTxtExpiresTooLongWarning extends SecurityTxtWarning
{

	public function __construct(?Throwable $previous = null)
	{
		$correctValue = (new DateTimeImmutable('+1 year midnight -1 sec'))->format(DATE_RFC3339);
		parent::__construct(
			'The value of the `Expires` should be less than a year into the future to avoid staleness',
			'draft-foudil-securitytxt-10',
			$correctValue,
			'Change the value of the `Expires` field to less than a year into the future',
			'2.5.5',
			previous: $previous,
		);
	}

}
