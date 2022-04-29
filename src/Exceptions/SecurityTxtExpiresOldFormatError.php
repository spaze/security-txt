<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Exceptions;

use DateTimeInterface;
use Throwable;

class SecurityTxtExpiresOldFormatError extends SecurityTxtError
{

	public function __construct(
		private readonly DateTimeInterface $expires,
		?Throwable $previous = null,
	) {
		$correctValue = $this->expires->format(DATE_RFC3339);
		parent::__construct(
			"The value of the `Expires` field follows the format defined in section 3.3 of RFC 5322 but it should be formatted according to the Internet profile of ISO 8601 as defined in RFC 3339 (`{$correctValue}`)",
			'draft-foudil-securitytxt-12',
			$correctValue,
			"Change the value of the `Expires` field to `{$correctValue}`",
			'3.5.5',
			previous: $previous,
		);
	}

}
