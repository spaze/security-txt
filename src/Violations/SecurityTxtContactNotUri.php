<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Violations;

use Spaze\SecurityTxt\Fields\SecurityTxtField;

class SecurityTxtContactNotUri extends SecurityTxtFieldNotUri
{

	public function __construct(string $uri)
	{
		$isEmail = (bool)filter_var($uri, FILTER_VALIDATE_EMAIL);
		parent::__construct(
			SecurityTxtField::Contact,
			$uri,
			'draft-foudil-securitytxt-03',
			($isEmail ? 'mailto:' : 'tel:') . $uri,
			$isEmail ? 'The value looks like an email address, add the "mailto" schema' : 'The value looks like a phone number, add the "tel" schema',
			'2.5.3',
		);
	}

}
