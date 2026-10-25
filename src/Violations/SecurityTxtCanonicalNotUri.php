<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Violations;

use Spaze\SecurityTxt\Fields\SecurityTxtField;

final class SecurityTxtCanonicalNotUri extends SecurityTxtFieldNotUri
{

	public function __construct(string $uri, SecurityTxtNotUriReason $reason = SecurityTxtNotUriReason::Unspecified, ?string $correctValue = null)
	{
		parent::__construct(func_get_args(), SecurityTxtField::Canonical, $uri, $reason, $correctValue, 'draft-foudil-securitytxt-05', '2.5.2');
	}

}
