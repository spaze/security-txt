<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser\LineProcessors;

use Spaze\SecurityTxt\Exceptions\SecurityTxtCanonicalNotHttpsError;
use Spaze\SecurityTxt\Fields\Canonical;
use Spaze\SecurityTxt\SecurityTxt;

class CanonicalAddFieldValue implements LineProcessor
{

	/**
	 * @throws SecurityTxtCanonicalNotHttpsError
	 */
	public function process(string $value, SecurityTxt $securityTxt): void
	{
		$canonical = new Canonical($value);
		$securityTxt->addCanonical($canonical);
	}

}
