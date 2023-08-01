<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Exceptions;

use Spaze\SecurityTxt\Fields\SecurityTxtField;
use Throwable;

class SecurityTxtPossibelFieldTypoWarning extends SecurityTxtWarning
{

	public function __construct(string $fieldName, SecurityTxtField $suggestion, string $line, ?Throwable $previous = null)
	{
		parent::__construct(
			"Field `{$fieldName}` may be a typo, did you mean `{$suggestion->value}`?",
			null,
			str_replace($fieldName, $suggestion->value, $line),
			"Change `{$fieldName}` to `{$suggestion->value}`",
			null,
			previous: $previous,
		);
	}

}
