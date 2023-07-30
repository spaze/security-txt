<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Exceptions;

use Throwable;

class SecurityTxtPreferredLanguagesCommonMistakeError extends SecurityTxtError
{

	public function __construct(int $position, string $mistake, ?string $correctValue, string $reason, ?Throwable $previous = null)
	{
		parent::__construct(
			"The language tag #{$position} `{$mistake}` in the `Preferred-Languages` field is not correct, {$reason}",
			'draft-foudil-securitytxt-05',
			$correctValue,
			'Use language tags as defined in RFC 5646, which usually means the shortest ISO 639 code',
			'2.5.8',
			previous: $previous,
		);
	}

}
