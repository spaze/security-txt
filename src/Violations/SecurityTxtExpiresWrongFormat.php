<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Violations;

use DateTimeImmutable;
use DateTimeInterface;

class SecurityTxtExpiresWrongFormat extends SecurityTxtSpecViolation
{

	public function __construct(?DateTimeInterface $expires = null)
	{
		$correctValue = $expires ? $expires->format(DATE_RFC3339) : new DateTimeImmutable('+1 year midnight -1 sec')->format(DATE_RFC3339);
		parent::__construct(
			func_get_args(),
			'The format of the value of the `Expires` field is wrong',
			[],
			'draft-foudil-securitytxt-09',
			$correctValue,
			'The `Expires` field should contain a date and time in the future formatted according to the Internet profile of ISO 8601 as defined in RFC 3339',
			[],
			'2.5.5',
		);
	}

}
