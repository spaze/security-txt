<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Violations;

use DateTimeImmutable;
use Spaze\SecurityTxt\Fields\Expires;

final class SecurityTxtExpiresTooLong extends SecurityTxtSpecViolation
{

	public function __construct()
	{
		$correctValue = new DateTimeImmutable('+1 year midnight -1 sec')->format(Expires::FORMAT);
		parent::__construct(
			func_get_args(),
			'The value of the `Expires` should be less than a year into the future to avoid staleness',
			[],
			'draft-foudil-securitytxt-10',
			$correctValue,
			'Change the value of the `Expires` field to less than a year into the future',
			[],
			'2.5.5',
		);
	}

}
