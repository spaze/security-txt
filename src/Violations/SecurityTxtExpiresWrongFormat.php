<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Violations;

use DateTimeImmutable;
use DateTimeInterface;

class SecurityTxtExpiresWrongFormat extends SecurityTxtSpecViolation
{

	public function __construct(?DateTimeInterface $expires = null)
	{
		if ($expires) {
			$correctValue = $expires->format(DATE_RFC3339);
			$howToFix = "Change the value of the `Expires` field to `$correctValue`";
		}
		parent::__construct(
			'The format of the value of the `Expires` field is wrong',
			'draft-foudil-securitytxt-09',
			$correctValue ?? (new DateTimeImmutable('+1 year midnight -1 sec'))->format(DATE_RFC3339),
			$howToFix ?? 'The `Expires` field should contain a date and time in the future formatted according to the Internet profile of ISO 8601 as defined in RFC 3339',
			'2.5.5',
		);
	}

}
