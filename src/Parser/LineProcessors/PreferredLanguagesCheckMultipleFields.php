<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser\LineProcessors;

use Spaze\SecurityTxt\Exceptions\SecurityTxtMultiplePreferredLanguagesError;
use Spaze\SecurityTxt\SecurityTxt;

class PreferredLanguagesCheckMultipleFields implements LineProcessor
{

	/**
	 * @throws SecurityTxtMultiplePreferredLanguagesError
	 */
	public function process(string $value, SecurityTxt $securityTxt): void
	{
		if ($securityTxt->getPreferredLanguages()) {
			throw new SecurityTxtMultiplePreferredLanguagesError();
		}
	}

}
