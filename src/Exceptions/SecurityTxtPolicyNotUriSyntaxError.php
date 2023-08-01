<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Exceptions;

use Spaze\SecurityTxt\Fields\SecurityTxtField;
use Throwable;

class SecurityTxtPolicyNotUriSyntaxError extends SecurityTxtFieldNotUriError
{

	public function __construct(string $uri, ?Throwable $previous = null)
	{
		parent::__construct(SecurityTxtField::Policy, $uri, 'draft-foudil-securitytxt-02', null, null, '2.5.7', $previous);
	}

}
