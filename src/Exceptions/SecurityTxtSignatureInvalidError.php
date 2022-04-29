<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Exceptions;

use Throwable;

class SecurityTxtSignatureInvalidError extends SecurityTxtError
{

	public function __construct(?Throwable $previous = null)
	{
		parent::__construct(
			'The file is digitally signed using an OpenPGP cleartext signature but the signature is not valid',
			'draft-foudil-securitytxt-01',
			null,
			'Sign the file again',
			'2.3',
			previous: $previous,
		);
	}

}
