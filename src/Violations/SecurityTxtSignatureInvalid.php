<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Violations;

class SecurityTxtSignatureInvalid extends SecurityTxtSpecViolation
{

	public function __construct()
	{
		parent::__construct(
			'The file is digitally signed using an OpenPGP cleartext signature but the signature is not valid',
			'draft-foudil-securitytxt-01',
			null,
			'Sign the file again',
			'2.3',
		);
	}

}
