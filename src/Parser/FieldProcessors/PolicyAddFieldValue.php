<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser\FieldProcessors;

use Override;
use Spaze\SecurityTxt\Fields\Policy;
use Spaze\SecurityTxt\SecurityTxt;

final class PolicyAddFieldValue implements FieldProcessor
{

	#[Override]
	public function process(string $value, SecurityTxt $securityTxt): void
	{
		$policy = new Policy($value);
		$securityTxt->addPolicy($policy);
	}

}
