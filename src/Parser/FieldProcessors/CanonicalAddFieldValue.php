<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser\FieldProcessors;

use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\Fields\Canonical;
use Spaze\SecurityTxt\SecurityTxt;

class CanonicalAddFieldValue implements FieldProcessor
{

	/**
	 * @throws SecurityTxtError
	 */
	public function process(string $value, SecurityTxt $securityTxt): void
	{
		$canonical = new Canonical($value);
		$securityTxt->addCanonical($canonical);
	}

}
