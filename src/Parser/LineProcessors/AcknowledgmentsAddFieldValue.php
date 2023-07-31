<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser\LineProcessors;

use Spaze\SecurityTxt\Fields\Acknowledgments;
use Spaze\SecurityTxt\SecurityTxt;

class AcknowledgmentsAddFieldValue implements LineProcessor
{

	public function process(string $value, SecurityTxt $securityTxt): void
	{
		$acknowledgments = new Acknowledgments($value);
		$securityTxt->addAcknowledgments($acknowledgments);
	}

}
