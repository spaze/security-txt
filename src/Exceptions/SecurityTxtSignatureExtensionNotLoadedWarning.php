<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Exceptions;

use Throwable;

class SecurityTxtSignatureExtensionNotLoadedWarning extends SecurityTxtWarning
{

	public function __construct(?Throwable $previous = null)
	{
		parent::__construct(
			'The `gnupg` extension is not available, cannot verify or create signatures',
			'draft-foudil-securitytxt-01',
			null,
			'Load the `gnupg` extension',
			'3.3',
			previous: $previous,
		);
	}

}
