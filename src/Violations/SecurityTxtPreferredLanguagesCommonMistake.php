<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Violations;

use Spaze\SecurityTxt\Fields\SecurityTxtField;

final class SecurityTxtPreferredLanguagesCommonMistake extends SecurityTxtSpecViolation
{

	/**
	 * @param literal-string $reason Goes into the format, so it must not be built from anything read from the file
	 * @param list<string> $reasonValues
	 */
	public function __construct(int $position, string $mistake, ?string $correctValue, string $reason, array $reasonValues)
	{
		parent::__construct(
			func_get_args(),
			// `#%s` and not `#{$position}`, a runtime number written into the format would stop it being a `literal-string`
			'The language tag #%s %s in the %s field is not correct, ' . $reason,
			[(string)$position, $mistake, SecurityTxtField::PreferredLanguages->value, ...$reasonValues],
			'draft-foudil-securitytxt-05',
			$correctValue,
			'Use language tags as defined in RFC 5646, which usually means the shortest ISO 639 code',
			[],
			'2.5.8',
		);
	}

}
