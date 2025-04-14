<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser\FieldProcessors;

use Override;
use Spaze\SecurityTxt\Fields\Hiring;
use Spaze\SecurityTxt\SecurityTxt;

final class HiringAddFieldValue implements FieldProcessor
{

	#[Override]
	public function process(string $value, SecurityTxt $securityTxt): void
	{
		$hiring = new Hiring($value);
		$securityTxt->addHiring($hiring);
	}

}
