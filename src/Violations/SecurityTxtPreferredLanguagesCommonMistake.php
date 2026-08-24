<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Violations;

use Spaze\SecurityTxt\Fields\SecurityTxtField;

final class SecurityTxtPreferredLanguagesCommonMistake extends SecurityTxtSpecViolation
{

	/**
	 * @param SecurityTxtPreferredLanguagesCommonMistakeReason|string $reason A string only when rebuilt from JSON, where the wire carries the case value, and `from()` refuses anything else
	 */
	public function __construct(int $position, string $mistake, ?string $correctValue, SecurityTxtPreferredLanguagesCommonMistakeReason|string $reason)
	{
		if (is_string($reason)) {
			$reason = SecurityTxtPreferredLanguagesCommonMistakeReason::from($reason);
		}
		parent::__construct(
			[$position, $mistake, $correctValue, $reason->value],
			// `#%s` and not `#{$position}`, a runtime number written into the format would stop it being a `literal-string`
			'The language tag #%s %s in the %s field is not correct, ' . $reason->getFormat(),
			[(string)$position, $mistake, SecurityTxtField::PreferredLanguages->value, ...$reason->getValues()],
			'draft-foudil-securitytxt-05',
			$correctValue,
			'Use language tags as defined in RFC 5646, which usually means the shortest ISO 639 code',
			[],
			'2.5.8',
		);
	}

}
