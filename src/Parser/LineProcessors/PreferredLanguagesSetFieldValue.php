<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser\LineProcessors;

use LogicException;
use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\Fields\PreferredLanguages;
use Spaze\SecurityTxt\SecurityTxt;
use Spaze\SecurityTxt\Violations\SecurityTxtPreferredLanguagesSeparatorNotComma;

class PreferredLanguagesSetFieldValue implements LineProcessor
{

	public function process(string $value, SecurityTxt $securityTxt): void
	{
		$regexp = '/\s*([,.;:])\s*/';
		$separators = preg_match_all($regexp, $value, $matches, flags: PREG_OFFSET_CAPTURE);
		$languages = @preg_split($regexp, $value); // intentionally @, converted to exception
		if (!$languages) {
			throw new LogicException('This should not happen');
		}
		if ($separators) {
			$wrongSeparators = [];
			foreach ($matches[1] as $match) {
				if ($match[0] !== ',') {
					$wrongSeparators[$match[0]][] = $match[1];
				}
			}
			if ($wrongSeparators) {
				throw new SecurityTxtError(new SecurityTxtPreferredLanguagesSeparatorNotComma($wrongSeparators, $languages));
			}
		}
		$securityTxt->setPreferredLanguages(new PreferredLanguages($languages));
	}

}
