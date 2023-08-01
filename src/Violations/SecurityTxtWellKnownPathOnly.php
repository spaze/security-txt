<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Violations;

class SecurityTxtWellKnownPathOnly extends SecurityTxtSpecViolation
{

	public function __construct()
	{
		parent::__construct(
			"`security.txt` not found at the top-level path",
			[],
			'draft-foudil-securitytxt-02',
			null,
			'Redirect the top-level file to the one under the `/.well-known/` path',
			[],
			'3',
		);
	}

}
