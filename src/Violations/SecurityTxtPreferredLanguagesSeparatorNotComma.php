<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Violations;

class SecurityTxtPreferredLanguagesSeparatorNotComma extends SecurityTxtSpecViolation
{

	/**
	 * @param array<string, list<int>> $wrongSeparators
	 * @param list<string> $languages
	 */
	public function __construct(array $wrongSeparators, array $languages)
	{
		$count = count($wrongSeparators);
		$separators = [];
		foreach ($wrongSeparators as $separator => $positions) {
			$separators[] = sprintf(
				'`%s` at %s %s characters from the start',
				$separator,
				count($positions) > 1 ? 'positions' : 'position',
				implode(', ', $positions),
			);
		}
		$message = sprintf(
			'The `Preferred-Languages` field %s (%s), separate multiple values with a comma (`,`)',
			$count > 1 ? 'uses wrong separators' : 'uses a wrong separator',
			implode('; ', $separators),
		);
		parent::__construct(
			$message,
			'draft-foudil-securitytxt-05',
			implode(', ', $languages),
			'Use comma (`,`) to list multiple languages in the `Preferred-Languages` field',
			'2.5.8',
		);
	}

}
