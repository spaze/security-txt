<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser\FieldProcessors;

use Override;
use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\Fields\Canonical;
use Spaze\SecurityTxt\SecurityTxt;

final class CanonicalAddFieldValue implements FieldProcessor
{

	/**
	 * @throws SecurityTxtError
	 */
	#[Override]
	public function process(string $value, SecurityTxt $securityTxt): void
	{
		$canonical = new Canonical($value);
		$securityTxt->addCanonical($canonical);
	}

}
