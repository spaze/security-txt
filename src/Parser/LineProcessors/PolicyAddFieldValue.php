<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser\LineProcessors;

use Spaze\SecurityTxt\Fields\Policy;
use Spaze\SecurityTxt\SecurityTxt;

class PolicyAddFieldValue implements LineProcessor
{

	public function process(string $value, SecurityTxt $securityTxt): void
	{
		$policy = new Policy($value);
		$securityTxt->addPolicy($policy);
	}

}
