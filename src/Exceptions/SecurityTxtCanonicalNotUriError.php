<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Exceptions;

use Spaze\SecurityTxt\Fields\SecurityTxtField;
use Throwable;

class SecurityTxtCanonicalNotUriError extends SecurityTxtFieldNotUriError
{

	public function __construct(string $uri, ?Throwable $previous = null)
	{
		parent::__construct(SecurityTxtField::Canonical, $uri, 'draft-foudil-securitytxt-05', null, null, '2.5.2', $previous);
	}

}
