<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser\FieldProcessors;

use Spaze\SecurityTxt\Fields\Hiring;
use Spaze\SecurityTxt\SecurityTxt;

class HiringAddFieldValue implements FieldProcessor
{

	public function process(string $value, SecurityTxt $securityTxt): void
	{
		$hiring = new Hiring($value);
		$securityTxt->addHiring($hiring);
	}

}
