<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser\LineProcessors;

use Spaze\SecurityTxt\Exceptions\SecurityTxtMultipleExpiresError;
use Spaze\SecurityTxt\SecurityTxt;

class ExpiresCheckMultipleFields implements LineProcessor
{

	/**
	 * @throws SecurityTxtMultipleExpiresError
	 */
	public function process(string $value, SecurityTxt $securityTxt): void
	{
		if ($securityTxt->getExpires()) {
			throw new SecurityTxtMultipleExpiresError();
		}
	}

}
