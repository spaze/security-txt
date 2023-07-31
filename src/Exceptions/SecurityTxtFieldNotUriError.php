<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Exceptions;

use Spaze\SecurityTxt\Fields\SecurityTxtField;
use Throwable;

abstract class SecurityTxtFieldNotUriError extends SecurityTxtError
{

	public function __construct(
		SecurityTxtField $field,
		string $uri,
		string $since,
		?string $correctValue,
		?string $howToFix,
		?string $specSection,
		?Throwable $previous = null,
	) {
		parent::__construct(
			"The `{$field->value}` value (`{$uri}`) doesn't follow the URI syntax described in RFC 3986, the scheme is missing",
			$since,
			$correctValue,
			$howToFix ?? 'Use a URI as the value',
			$specSection,
			previous: $previous,
		);
	}

}
