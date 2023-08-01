<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Exceptions;

use Spaze\SecurityTxt\Fields\SecurityTxtField;
use Throwable;

class SecurityTxtEncryptionNotHttpsError extends SecurityTxtFieldUriNotHttpsError
{

	public function __construct(string $uri, ?Throwable $previous = null)
	{
		parent::__construct(SecurityTxtField::Encryption, $uri, '2.5.4', $previous);
	}

}
