<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Exceptions;

use Spaze\SecurityTxt\Fields\SecurityTxtField;
use Throwable;

class SecurityTxtAcknowledgmentsNotUriSyntaxError extends SecurityTxtFieldNotUriError
{

	public function __construct(string $uri, ?Throwable $previous = null)
	{
		parent::__construct(SecurityTxtField::Acknowledgments, $uri, 'draft-foudil-securitytxt-03', null, null, '2.5.1', $previous);
	}

}
