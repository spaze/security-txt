<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Exceptions;

use Throwable;

class SecurityTxtWellKnownPathOnlyWarning extends SecurityTxtWarning
{

	public function __construct(?Throwable $previous = null)
	{
		parent::__construct(
			"`security.txt` not found at the top-level path",
			'draft-foudil-securitytxt-02',
			null,
			'Redirect the top-level file to the one under the `/.well-known/` path',
			'3',
			previous: $previous,
		);
	}

}
