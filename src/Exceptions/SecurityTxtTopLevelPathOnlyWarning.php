<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Exceptions;

use Throwable;

class SecurityTxtTopLevelPathOnlyWarning extends SecurityTxtWarning
{

	public function __construct(?Throwable $previous = null)
	{
		parent::__construct(
			"`security.txt` wasn't found under the `/.well-known/` path",
			'draft-foudil-securitytxt-02',
			null,
			'Move the `security.txt` file from the top-level location under the `/.well-known/` path and redirect `/security.txt` to `/.well-known/security.txt`',
			'4',
			previous: $previous,
		);
	}

}
