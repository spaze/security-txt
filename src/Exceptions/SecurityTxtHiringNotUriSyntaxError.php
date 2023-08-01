<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Exceptions;

use Spaze\SecurityTxt\Fields\SecurityTxtField;
use Throwable;

class SecurityTxtHiringNotUriSyntaxError extends SecurityTxtFieldNotUriError
{

	public function __construct(string $uri, ?Throwable $previous = null)
	{
		parent::__construct(SecurityTxtField::Hiring, $uri, 'draft-foudil-securitytxt-03', null, null, '2.5.6', $previous);
	}

}
