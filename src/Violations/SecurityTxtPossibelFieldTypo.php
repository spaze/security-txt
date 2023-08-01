<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Violations;

use Spaze\SecurityTxt\Fields\SecurityTxtField;

class SecurityTxtPossibelFieldTypo extends SecurityTxtSpecViolation
{

	public function __construct(string $fieldName, SecurityTxtField $suggestion, string $line)
	{
		parent::__construct(
			"Field `{$fieldName}` may be a typo, did you mean `{$suggestion->value}`?",
			null,
			str_replace($fieldName, $suggestion->value, $line),
			"Change `{$fieldName}` to `{$suggestion->value}`",
			null,
		);
	}

}
