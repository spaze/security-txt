<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Exceptions;

use Throwable;

class SecurityTxtNoContactError extends SecurityTxtError
{

	public function __construct(?Throwable $previous = null)
	{
		parent::__construct(
			'The `Contact` field must always be present',
			'draft-foudil-securitytxt-00',
			null,
			'Add at least one `Contact` field with a value that follows the URI syntax described in RFC 3986. This means that "mailto" and "tel" URI schemes must be used when specifying email addresses and telephone numbers, e.g. mailto:security@example.com',
			'2.5.3',
			['2.5.4'],
			$previous,
		);
	}

}
