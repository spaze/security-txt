<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Exceptions;

use Spaze\SecurityTxt\Fields\SecurityTxtField;
use Throwable;

class SecurityTxtPolicyNotHttpsError extends SecurityTxtFieldUriNotHttpsError
{

	public function __construct(string $uri, ?Throwable $previous = null)
	{
		parent::__construct(SecurityTxtField::Policy, $uri, '2.5.7', $previous);
	}

}
