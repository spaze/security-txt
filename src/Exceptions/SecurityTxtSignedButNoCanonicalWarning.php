<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Exceptions;

use Throwable;

class SecurityTxtSignedButNoCanonicalWarning extends SecurityTxtWarning
{

	public function __construct(?Throwable $previous = null)
	{
		parent::__construct(
			'When digital signatures are used, it is also recommended that organizations use the `Canonical` field',
			'draft-foudil-securitytxt-05',
			null,
			'Add `Canonical` field pointing where the `security.txt` file is located',
			'3.4',
			['3.5.2'],
			previous: $previous,
		);
	}

}
