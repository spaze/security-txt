<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Violations;

use Spaze\SecurityTxt\Fields\SecurityTxtField;

final class SecurityTxtHiringNotUri extends SecurityTxtFieldNotUri
{

	public function __construct(string $uri, SecurityTxtNotUriReason $reason = SecurityTxtNotUriReason::Unspecified, ?string $correctValue = null)
	{
		parent::__construct(func_get_args(), SecurityTxtField::Hiring, $uri, $reason, $correctValue, 'draft-foudil-securitytxt-03', '2.5.6');
	}

}
