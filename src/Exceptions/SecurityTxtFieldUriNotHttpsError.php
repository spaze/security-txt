<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Exceptions;

use Spaze\SecurityTxt\Fields\SecurityTxtField;
use Throwable;

abstract class SecurityTxtFieldUriNotHttpsError extends SecurityTxtError
{

	public function __construct(SecurityTxtField $field, string $uri, string $specSection, ?Throwable $previous = null)
	{
		parent::__construct(
			sprintf('If the `%s` field indicates a web URI, then it must begin with "https://"', $field->value),
			'draft-foudil-securitytxt-06',
			preg_replace('~^http://~', 'https://', $uri),
			sprintf('Make sure the `%s` field points to an https:// URI', $field->value),
			$specSection,
			previous: $previous,
		);
	}

}
