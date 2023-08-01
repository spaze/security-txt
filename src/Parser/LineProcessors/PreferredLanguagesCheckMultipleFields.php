<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser\LineProcessors;

use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\SecurityTxt;
use Spaze\SecurityTxt\Violations\SecurityTxtMultiplePreferredLanguages;

class PreferredLanguagesCheckMultipleFields implements LineProcessor
{

	/**
	 * @throws SecurityTxtError
	 */
	public function process(string $value, SecurityTxt $securityTxt): void
	{
		if ($securityTxt->getPreferredLanguages()) {
			throw new SecurityTxtError(new SecurityTxtMultiplePreferredLanguages());
		}
	}

}
