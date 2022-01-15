<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser\LineProcessors;

use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtWarning;
use Spaze\SecurityTxt\SecurityTxt;

interface LineProcessor
{

	/**
	 * @throws SecurityTxtError|SecurityTxtWarning
	 */
	public function process(string $value, SecurityTxt $securityTxt): void;

}
